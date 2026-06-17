/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2026 Sadie Powell <sadie@sadiepowell.dev>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "clientprotocolmsg.h"
#include "modules/ircv3_batch.h"
#include "modules/isupport.h"
#include "modules/isupport.h"

enum
{
	// From RFC 2812.
	RPL_MYINFO = 4,

	// From RFC 1459.
	RPL_LUSERCLIENT = 251,
};

class ExtendedISupportCap final
	: public Cap::Capability
{
public:
	IRCv3::Batch::CapReference batchcap;
	ISupport::API isupportapi;

	ExtendedISupportCap(Module* mod)
		: Cap::Capability(mod, "draft/extended-isupport")
		, batchcap(mod)
		, isupportapi(mod)
	{
	}

	bool OnList(LocalUser* user) override
	{
		// The specification requires batch so don't show the cap without it.
		// The ISupport API should always be available but its better to be safe.
		return batchcap && isupportapi;
	}

	bool OnRequest(LocalUser* user, bool adding) override
	{
		return OnList(user);
	}
};

class CommandISupport final
	: public SplitCommand
{
public:
	BoolExtItem earlyisupport;
	ExtendedISupportCap extendedisupportcap;
	bool sending = false;

	CommandISupport(Module* mod)
		: SplitCommand(mod, "ISUPPORT")
		, earlyisupport(mod, "early-isupport", ExtensionType::USER)
		, extendedisupportcap(mod)
	{
		works_before_reg = true;
	}

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
	{
		if (!extendedisupportcap.IsEnabled(user))
		{
			user->WriteNumeric(ERR_UNKNOWNCOMMAND, this->name, INSP_FORMAT("You need the {} client capability to use this command",
				extendedisupportcap.GetName()));
			return CmdResult::FAILURE;
		}

		// This should always be available but its better to be safe.
		if (!extendedisupportcap.isupportapi)
			return CmdResult::FAILURE;

		sending = true;
		extendedisupportcap.isupportapi->SendTo(user);
		sending = false;

		if (!user->IsFullyConnected())
			earlyisupport.Set(user);

		return CmdResult::SUCCESS;
	}
};

class ModuleExtendedISupport final
	: public Module
	, public ClientProtocol::EventHook
	, public ISupport::EventListener
{
private:
	IRCv3::Batch::Batch batch;
	IRCv3::Batch::API batchmanager;
	CommandISupport isupportcmd;
	bool skipisupport = true;

public:
	ModuleExtendedISupport()
		: Module(VF_VENDOR, "Provides support for the DRAFT IRCv3 Extended ISupport specification.")
		, ClientProtocol::EventHook(this, "NUMERIC")
		, ISupport::EventListener(this)
		, batch("draft/extended-isupport")
		, batchmanager(this)
		, isupportcmd(this)
	{
	}

	ModResult OnNumeric(User* user, const Numeric::Numeric& numeric) override
	{
		if (!IS_LOCAL(user) || user->IsFullyConnected())
			return MOD_RES_PASSTHRU;

		// Numeric order on connect is 004 -> 005 -> 251.
		switch (numeric.GetNumeric())
		{
			case RPL_MYINFO:
				skipisupport = true;
				break;

			case RPL_ISUPPORT:
				if (skipisupport)
					return MOD_RES_DENY;
				break;

			case RPL_LUSERCLIENT:
				skipisupport = false;
				break;

			default:
				break; // Nothing to do.
		}
		return MOD_RES_PASSTHRU;
	}

	void OnPostConnect(User* user) override
	{
		if (IS_LOCAL(user))
			isupportcmd.earlyisupport.Unset(user);
	}

	ModResult OnPreEventSend(LocalUser* user, const ClientProtocol::Event& ev, ClientProtocol::MessageList& messagelist) override
	{
		if (!batchmanager || !isupportcmd.extendedisupportcap.batchcap.IsEnabled(user))
			return MOD_RES_PASSTHRU; // No batch support.

		if (!isupportcmd.extendedisupportcap.IsEnabled(user))
			return MOD_RES_PASSTHRU; // No extended-isupport support.

		for (auto* message : messagelist)
		{
			auto* numeric = static_cast<ClientProtocol::Messages::Numeric*>(message);
			if (numeric->GetNumeric() != RPL_ISUPPORT)
				continue; // Wrong numeric.

			if (!batch.IsRunning())
				batchmanager->Start(batch);
			batch.AddToBatch(*numeric);
		}
		return MOD_RES_PASSTHRU;
	}

	void OnPostEventSend(LocalUser* user, const ClientProtocol::Event& ev, const ClientProtocol::MessageList& messagelist) override
	{
		if (batch.IsRunning())
			batchmanager->End(batch);
	}

	ModResult OnSendISupportDiff(LocalUser* user, const ISupport::TokenMap& tokens) override
	{
		if (user->IsFullyConnected())
			return MOD_RES_PASSTHRU; // The core handles fully connected users.

		return isupportcmd.earlyisupport.Get(user) ? MOD_RES_ALLOW : MOD_RES_PASSTHRU;
	}
};

MODULE_INIT(ModuleExtendedISupport)
