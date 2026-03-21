/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2019 linuxdaemon <linuxdaemon.irc@gmail.com>
 *   Copyright (C) 2013-2015 Attila Molnar <attilamolnar@hush.com>
 *   Copyright (C) 2013, 2017-2024 Sadie Powell <sadie@witchery.services>
 *   Copyright (C) 2012 Robby <robby@chatbelgie.be>
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2006, 2008 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2006, 2008 Craig Edwards <brain@inspircd.org>
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
#include "modules/account.h"
#include "modules/callerid.h"
#include "modules/ctctags.h"
#include "modules/exemption.h"
#include "modules/extban.h"
#include "modules/ircv3_replies.h"
#include "modules/isupport.h"
#include "modules/who.h"
#include "modules/whois.h"

enum
{
	// From ircd-hybrid?
	ERR_NEEDREGGEDNICK = 477,

	// From IRCv3 sasl-3.1.
	RPL_LOGGEDIN = 900,
	RPL_LOGGEDOUT = 901
};

struct SharedData final
{
	// A dynamic reference to the account provider API.
	Account::ProviderAPI accountproviderapi;

	// A reference to the account-registration cap.
	Cap::Capability& accountregistrationcap;

	// A pointer to the REGISTER command.
	Command* cmdregister;

	// A pointer to the VERIFY command.
	Command* cmdverify;

	// API for sending a FAIL message.
	IRCv3::Replies::Fail failrpl;

	// The registraton flags sent by services.
	uint8_t flags = Account::REGISTER_NONE;

	// Provider for the REGISTER event.
	ClientProtocol::EventProvider registerevprov;

	// Provider for the VERIFY event.
	ClientProtocol::EventProvider verifyevprov;

	SharedData(Module* mod, Cap::Capability& cap, Command& cmdr, Command& cmdv)
		: accountproviderapi(mod)
		, accountregistrationcap(cap)
		, cmdregister(&cmdr)
		, cmdverify(&cmdv)
		, failrpl(mod)
		, registerevprov(mod, cmdregister->name)
		, verifyevprov(mod, cmdverify->name)
	{
	}
};

class AccountExtItemImpl final
	: public StringExtItem
{
	Events::ModuleEventProvider eventprov;

public:
	AccountExtItemImpl(Module* mod)
		: StringExtItem(mod, "accountname", ExtensionType::USER, true)
		, eventprov(mod, "event/account")
	{
	}

	void FromNetwork(Extensible* container, const std::string& value) noexcept override
	{
		if (container->extype != this->extype)
			return;

		StringExtItem::FromNetwork(container, value);

		User* user = static_cast<User*>(container);
		if (IS_LOCAL(user))
		{
			if (value.empty())
			{
				// Logged out.
				user->WriteNumeric(RPL_LOGGEDOUT, user->GetMask(), "You are now logged out");
			}
			else
			{
				// Logged in.
				user->WriteNumeric(RPL_LOGGEDIN, user->GetMask(), value, INSP_FORMAT("You are now logged in as {}", value));
			}
		}

		eventprov.Call(&Account::EventListener::OnAccountChange, user, value);
	}
};

class AccountRegistrationCap final
	: public Cap::Capability
{
private:
	std::string capvalue;

	bool OnRequest(LocalUser* user, bool adding) override
	{
		return OnList(user);
	}

	bool OnList(LocalUser* user) override
	{
		return !!data.accountproviderapi;
	}

	const std::string* GetValue(LocalUser* user) const override
	{
		return &capvalue;
	}

public:
	SharedData& data;

	// Updates the value of the capability and notifies clients if it has changed.
	void UpdateValue(uint8_t rf)
	{
		std::string newcapvalue;
		if (rf & Account::REGISTER_BEFORE_CONNECT)
			newcapvalue.append("before-connect");

		if (rf & Account::REGISTER_CUSTOM_ACCOUNT_NAME)
			newcapvalue.append(newcapvalue.empty() ? "" : ",").append("custom-account-name");

		if (rf & Account::REGISTER_EMAIL_REQUIRED)
			newcapvalue.append(newcapvalue.empty() ? "" : ",").append("email-required");

		data.flags = rf;
		if (newcapvalue != capvalue)
		{
			capvalue = newcapvalue;
			NotifyValueChange();
		}
	}

	AccountRegistrationCap(Module* mod, SharedData& sd)
		: Cap::Capability(mod, "draft/account-registration")
		, data(sd)
	{
	}
};

class CommandRegister final
	: public SplitCommand
{
private:
	SharedData& data;

public:
	CommandRegister(Module* mod, SharedData& sd)
		: SplitCommand(mod, "REGISTER", 3)
		, data(sd)
	{
		syntax = { "<account>|* <email>|* <password>" };
		works_before_reg = true;
	}

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
	{
		if (!data.accountregistrationcap.IsEnabled(user))
			return CmdResult::FAILURE;

		if (!user->IsFullyConnected() && !(data.flags & Account::REGISTER_BEFORE_CONNECT))
		{
			data.failrpl.Send(user, this, "COMPLETE_CONNECTION_REQUIRED", "You must be fully connected to use this command.");
			return CmdResult::FAILURE;
		}

		auto account = user->nick;
		if (parameters[0] != "*" && !irc::equals(parameters[0], user->nick))
		{
			if (!(data.flags & Account::REGISTER_CUSTOM_ACCOUNT_NAME))
			{
				data.failrpl.Send(user, this, "ACCOUNT_NAME_MUST_BE_NICK", parameters[0], "Your account name must be your nickname on this network.");
				return CmdResult::FAILURE;
			}

			if (!ServerInstance->IsNick(parameters[0]))
			{
				data.failrpl.Send(user, this, "BAD_ACCOUNT_NAME",  parameters[0], "The account name you specified is invalid");
				return CmdResult::FAILURE;
			}

			account = parameters[0];
		}
		else if (!(user->connected & User::CONN_USER))
		{
			data.failrpl.Send(user, this, "NEED_NICK", '*', "You must have picked a nickname to use this command.");
			return CmdResult::FAILURE;
		}

		if (parameters[1] == "*" && (data.flags & Account::REGISTER_EMAIL_REQUIRED))
		{
			data.failrpl.Send(user, this, "INVALID_EMAIL", account, "The email address you specified is invalid.");
			return CmdResult::FAILURE;
		}

		if (!data.accountproviderapi)
		{
			data.failrpl.Send(user, this, "TEMPORARILY_UNAVAILABLE", account, "Accounts can not be registered right now. Please try again later.");
			return CmdResult::FAILURE;
		}

		data.accountproviderapi->Register(user, account, parameters[1], parameters[2]);
		return CmdResult::SUCCESS;
	}
};

class CommandVerify final
	: public SplitCommand
{
private:
	SharedData& data;

public:
	CommandVerify(Module* mod, SharedData& sd)
		: SplitCommand(mod, "VERIFY", 2)
		, data(sd)
	{
		syntax = { "<account>|* <code>" };
		works_before_reg = true;
	}

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
	{
		if (!data.accountregistrationcap.IsEnabled(user))
			return CmdResult::FAILURE;

		if (!user->IsFullyConnected() && !(data.flags & Account::REGISTER_BEFORE_CONNECT))
		{
			data.failrpl.Send(user, this, "COMPLETE_CONNECTION_REQUIRED", "You must be fully connected to use this command.");
			return CmdResult::FAILURE;
		}

		const auto& account = parameters[0] == "*" ? user->nick : parameters[0];
		if (!data.accountproviderapi)
		{
			data.failrpl.Send(user, this, "TEMPORARILY_UNAVAILABLE", account, "Accounts can not be verified right now. Please try again later.");
			return CmdResult::FAILURE;
		}

		data.accountproviderapi->Verify(user, account, parameters[1]);
		return CmdResult::SUCCESS;
	}
};

class AccountAPIImpl final
	: public Account::APIBase
{
private:
	AccountExtItemImpl accountext;
	StringExtItem accountidext;
	ListExtItem<Account::NickList> accountnicksext;
	UserModeReference identifiedmode;

	AccountRegistrationCap& accountregistrationcap;
	SharedData& data;

public:
	AccountAPIImpl(Module* mod, AccountRegistrationCap& cap, SharedData& sd)
		: Account::APIBase(mod)
		, accountext(mod)
		, accountidext(mod, "accountid", ExtensionType::USER, true)
		, accountnicksext(mod, "accountnicks", ExtensionType::USER, true)
		, identifiedmode(mod, "u_registered")
		, accountregistrationcap(cap)
		, data(sd)
	{
	}

	std::string* GetAccountId(const User* user) const override
	{
		return accountidext.Get(user);
	}

	std::string* GetAccountName(const User* user) const override
	{
		return accountext.Get(user);
	}

	Account::NickList* GetAccountNicks(const User* user) const override
	{
		return accountnicksext.Get(user);
	}

	bool IsIdentifiedToNick(const User* user) override
	{
		if (user->IsModeSet(identifiedmode))
			return true; // User has +r set.

		// Check whether their current nick is in their nick list.
		Account::NickList* nicks = accountnicksext.Get(user);
		return nicks && nicks->find(user->nick) != nicks->end();
	}

	void RegisterCallback(LocalUser* user, const std::string& account, const std::string& code, const std::string& message) override
	{
		ClientProtocol::Message protomsg("REGISTER");
		protomsg.PushParamRef(code);
		protomsg.PushParamRef(account);
		protomsg.PushParamRef(message);

		ClientProtocol::Event protoev(data.registerevprov, protomsg);
		user->Send(protoev);
	}

	void VerifyCallback(LocalUser* user, const std::string& account, const std::string& message) override
	{
		ClientProtocol::Message protomsg("VERIFY");
		protomsg.PushParam("SUCCESS");
		protomsg.PushParamRef(account);
		protomsg.PushParamRef(message);

		ClientProtocol::Event protoev(data.registerevprov, protomsg);
		user->Send(protoev);
	}

	void SetRegisterFlags(uint8_t rf) override
	{
		accountregistrationcap.UpdateValue(rf);
	}
};

class AccountExtBan final
	: public ExtBan::MatchingBase
{
private:
	AccountAPIImpl& accountapi;

public:
	AccountExtBan(Module* Creator, AccountAPIImpl& AccountAPI)
		: ExtBan::MatchingBase(Creator, "account", 'R')
		, accountapi(AccountAPI)
	{
	}

	bool IsMatch(User* user, Channel* channel, const std::string& text) override
	{
		const auto* nicks = accountapi.GetAccountNicks(user);
		if (nicks)
		{
			for (const auto& nick : *nicks)
			{
				if (InspIRCd::Match(nick, text))
					return true;
			}
		}

		const auto* account = accountapi.GetAccountName(user);
		return account && InspIRCd::Match(*account, text);
	}
};

class UnauthedExtBan final
	: public ExtBan::MatchingBase
{
private:
	AccountAPIImpl& accountapi;

public:
	UnauthedExtBan(Module* Creator, AccountAPIImpl& AccountAPI)
		: ExtBan::MatchingBase(Creator, "unauthed", 'U')
		, accountapi(AccountAPI)
	{
	}

	bool IsMatch(User* user, Channel* channel, const std::string& text) override
	{
		const std::string* account = accountapi.GetAccountName(user);
		return !account && channel->CheckBan(user, text);
	}
};

class ModuleAccount final
	: public Module
	, public CTCTags::EventListener
	, public ISupport::EventListener
	, public Who::EventListener
	, public Whois::EventListener
{
private:
	SharedData data;
	CallerID::API calleridapi;
	CheckExemption::EventProvider exemptionprov;
	SimpleChannelMode reginvitemode;
	SimpleChannelMode regmoderatedmode;
	SimpleUserMode regdeafmode;
	AccountRegistrationCap accountregistrationcap;
	CommandRegister cmdregister;
	CommandVerify cmdverify;
	AccountAPIImpl accountapi;
	AccountExtBan accountextban;
	UnauthedExtBan unauthedextban;

public:
	ModuleAccount()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Adds support for user accounts.")
		, CTCTags::EventListener(this)
		, ISupport::EventListener(this)
		, Who::EventListener(this)
		, Whois::EventListener(this)
		, data(this, accountregistrationcap, cmdregister, cmdverify)
		, calleridapi(this)
		, exemptionprov(this)
		, reginvitemode(this, "reginvite", 'R')
		, regmoderatedmode(this, "regmoderated", 'M')
		, regdeafmode(this, "regdeaf", 'R')
		, accountregistrationcap(this, data)
		, cmdregister(this, data)
		, cmdverify(this, data)
		, accountapi(this, accountregistrationcap, data)
		, accountextban(this, accountapi)
		, unauthedextban(this, accountapi)
	{
	}

	void OnBuildISupport(ISupport::TokenMap& tokens) override
	{
		tokens["ACCOUNTEXTBAN"] = accountextban.GetLetter()
			? INSP_FORMAT("{},{}", accountextban.GetName(), accountextban.GetLetter())
			: accountextban.GetName();
	}

	ModResult OnWhoLine(const Who::Request& request, LocalUser* source, User* user, Membership* memb, Numeric::Numeric& numeric) override
	{
		size_t flag_index;
		if (!request.GetFieldIndex('f', flag_index))
			return MOD_RES_PASSTHRU;

		if (accountapi.IsIdentifiedToNick(user))
			numeric.GetParams()[flag_index].push_back('r');

		return MOD_RES_PASSTHRU;
	}

	void OnWhois(Whois::Context& whois) override
	{
		const std::string* account = accountapi.GetAccountName(whois.GetTarget());
		if (account)
			whois.SendLine(RPL_WHOISACCOUNT, *account, "is logged in as");

		if (accountapi.IsIdentifiedToNick(whois.GetTarget()))
			whois.SendLine(RPL_WHOISREGNICK, "is a registered nick");
	}

	ModResult HandleMessage(User* user, const MessageTarget& target)
	{
		if (!IS_LOCAL(user))
			return MOD_RES_PASSTHRU;


		const std::string* account = accountapi.GetAccountName(user);
		switch (target.type)
		{
			case MessageTarget::TYPE_CHANNEL:
			{
				auto* targetchan = target.Get<Channel>();

				if (!targetchan->IsModeSet(regmoderatedmode) || account)
					return MOD_RES_PASSTHRU;

				if (exemptionprov.Check(user, targetchan, "regmoderated") == MOD_RES_ALLOW)
					return MOD_RES_PASSTHRU;

				// User is messaging a +M channel and is not registered or exempt.
				user->WriteNumeric(ERR_NEEDREGGEDNICK, targetchan->name, "You need to be identified to a registered account to message this channel");
				return MOD_RES_DENY;
			}
			case MessageTarget::TYPE_USER:
			{
				auto* targetuser = target.Get<User>();
				if (!targetuser->IsModeSet(regdeafmode)  || account)
					return MOD_RES_PASSTHRU;

				if (calleridapi && calleridapi->IsOnAcceptList(user, targetuser))
					return MOD_RES_PASSTHRU;

				// User is messaging a +R user and is not registered or on an accept list.
				user->WriteNumeric(ERR_NEEDREGGEDNICK, targetuser->nick, "You need to be identified to a registered account to message this user");
				return MOD_RES_DENY;
			}
			case MessageTarget::TYPE_SERVER:
				break;
		}
		return MOD_RES_PASSTHRU;
	}

	ModResult OnUserPreMessage(User* user, MessageTarget& target, MessageDetails& details) override
	{
		return HandleMessage(user, target);
	}

	ModResult OnUserPreTagMessage(User* user, MessageTarget& target, CTCTags::TagMessageDetails& details) override
	{
		return HandleMessage(user, target);
	}

	ModResult OnUserPreJoin(LocalUser* user, Channel* chan, const std::string& cname, std::string& privs, const std::string& keygiven, bool override) override
	{
		if (override)
			return MOD_RES_PASSTHRU;


		const std::string* account = accountapi.GetAccountName(user);
		if (chan)
		{
			if (chan->IsModeSet(reginvitemode))
			{
				if (!account)
				{
					// joining a +R channel and not identified
					user->WriteNumeric(ERR_NEEDREGGEDNICK, chan->name, "You need to be identified to a registered account to join this channel");
					return MOD_RES_DENY;
				}
			}
		}
		return MOD_RES_PASSTHRU;
	}

	ModResult OnPreOperLogin(LocalUser* user, const std::shared_ptr<OperAccount>& oper, bool automatic) override
	{
		const std::string accountstr = oper->GetConfig()->getString("account");
		if (accountstr.empty())
			return MOD_RES_PASSTHRU;

		const std::string* accountid = accountapi.GetAccountId(user);
		const std::string* accountname = accountapi.GetAccountName(user);

		irc::spacesepstream accountstream(accountstr);
		for (std::string account; accountstream.GetToken(account); )
		{
			if (accountid && irc::equals(account, *accountid))
				return MOD_RES_PASSTHRU; // Matches on account id.

			if (accountname && irc::equals(account, *accountname))
				return MOD_RES_PASSTHRU; // Matches on account name.
		}

		if (!automatic)
		{
			ServerInstance->SNO.WriteGlobalSno('o', "{} ({}) [{}] failed to log into the \x02{}\x02 oper account because they are not logged into the correct user account.",
				user->nick, user->GetRealUserHost(), user->GetAddress(), oper->GetName());
		}
		return MOD_RES_DENY; // Account required but it does not match.
	}

	ModResult OnPreChangeConnectClass(LocalUser* user, const std::shared_ptr<ConnectClass>& klass, std::optional<Numeric::Numeric>& errnum) override
	{
		const char* error = nullptr;
		if (insp::equalsci(klass->config->getString("requireaccount"), "nick"))
		{
			if (!accountapi.GetAccountName(user) && !accountapi.IsIdentifiedToNick(user))
				error = "an account matching their current nickname";
		}
		else if (klass->config->getBool("requireaccount"))
		{
			if (!accountapi.GetAccountName(user))
				error = "an account";
		}

		if (error)
		{
			ServerInstance->Logs.Debug("CONNECTCLASS", "The {} connect class is not suitable as it requires the user to be logged into {}.",
				klass->GetName(), error);
			return MOD_RES_DENY;
		}
		return MOD_RES_PASSTHRU;
	}
};

MODULE_INIT(ModuleAccount)
