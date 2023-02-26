/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2023 Sadie Powell <sadie@witchery.services>
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
#include "modules/cap.h"

class SharedData final
{
public:
	// The oper-tag capability.
	Cap::Capability opertagcap;

	// Reference to the hideoper mode.
	UserModeReference hideopermode;

	SharedData(const WeakModulePtr& mod)
		: opertagcap(mod, "draft/oper-tag")
		, hideopermode(mod, "hideoper")
	{
	}
};

class OperTag final
	: public ClientProtocol::MessageTagProvider
{
private:
	SharedData& data;

public:
	// <opertags:hideopername> from the config.
	bool hideopername;

	OperTag(const WeakModulePtr& mod, SharedData& sd)
		: ClientProtocol::MessageTagProvider(mod)
		, data(sd)
	{
	}

	void OnPopulateTags(ClientProtocol::Message& msg) override
	{
		const User* user = msg.GetSourceUser();
		if (user && user->IsOper() && !user->IsModeSet(data.hideopermode))
			msg.AddTag("draft/oper", this, hideopername ? "" : user->oper->GetName());
	}

	bool ShouldSendTag(LocalUser* user, const ClientProtocol::MessageTagData& tagdata) override
	{
		return data.opertagcap.IsEnabled(user);
	}
};

class OperRoleTag final
	: public ClientProtocol::MessageTagProvider
{
private:
	SharedData& data;

public:
	// <security:genericoper> from the config.
	bool genericoper;

	OperRoleTag(const WeakModulePtr& mod, SharedData& sd)
		: ClientProtocol::MessageTagProvider(mod)
		, data(sd)
	{
	}

	void OnPopulateTags(ClientProtocol::Message& msg) override
	{
		const User* user = msg.GetSourceUser();
		if (user && user->IsOper() && !user->IsModeSet(data.hideopermode))
			msg.AddTag("draft/oper-role", this, user->oper->GetType());
	}

	bool ShouldSendTag(LocalUser* user, const ClientProtocol::MessageTagData& tagdata) override
	{
		return !genericoper && data.opertagcap.IsEnabled(user);
	}
};

class ModuleIRCv3OperTag final
	: public Module
{
private:
	SharedData data;
	OperTag opertag;
	OperRoleTag operroletag;

public:
	ModuleIRCv3OperTag()
		: Module(VF_VENDOR, "Provides the draft IRCv3 oper and oper-role message tags.")
		, data(weak_from_this())
		, opertag(weak_from_this(), data)
		, operroletag(weak_from_this(), data)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& security = ServerInstance->Config->ConfValue("security");
		operroletag.genericoper = security->getBool("genericoper");

		const auto& opertags = ServerInstance->Config->ConfValue("opertags");
		opertag.hideopername = opertags->getBool("hideopername", operroletag.genericoper);
	}
};

MODULE_INIT(ModuleIRCv3OperTag)
