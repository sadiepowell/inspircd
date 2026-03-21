/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2022-2023 Sadie Powell <sadie@witchery.services>
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


#pragma once

#include "event.h"

namespace Account
{
	class API;
	class APIBase;
	class EventListener;
	class ProviderAPI;
	class ProviderAPIBase;

	/** Encapsulates a list of nicknames associated with an account. */
	typedef insp::flat_set<std::string, irc::insensitive_swo> NickList;

	enum RegisterFlags
		: uint8_t
	{
		/** No special flags apply to the REGISTER command. */
		REGISTER_NONE = 0,

		/** The REGISTER command can be used when not fully connected. */
		REGISTER_BEFORE_CONNECT = 1,

		/** The REGISTER command can contain a custom account name. */
		REGISTER_CUSTOM_ACCOUNT_NAME = 2,

		/** The REGISTER command requires an email address. */
		REGISTER_EMAIL_REQUIRED = 4,
	};
}

/** Defines the interface for the account API. */
class Account::APIBase
	: public DataProvider
{
public:
	APIBase(Module* parent)
		: DataProvider(parent, "accountapi")
	{
	}

	/** Retrieves the account identifier of the specified user.
	 * @param user The user to retrieve the account identifier of.
	 * @return If the user is logged in to an account then the account identifier; otherwise, nullptr.
	 */
	virtual std::string* GetAccountId(const User* user) const = 0;

	/** Retrieves the account name of the specified user.
	 * @param user The user to retrieve the account name of.
	 * @return If the user is logged in to an account then the account name; otherwise, nullptr.
	 */
	virtual std::string* GetAccountName(const User* user) const = 0;

	/** Retrieves the account nicks of the specified user.
	 * @param user The user to retrieve the account nicks of.
	 * @return If the user is logged in to an account then the account nicks; otherwise, nullptr.
	 */
	virtual NickList* GetAccountNicks(const User* user) const = 0;

	/** Determines whether a user is identified to their nickname.
	* @param user The user to check the identification status of.
	* @return If the user is identified to their nickname then true; otherwise, false.
	*/
	virtual bool IsIdentifiedToNick(const User* user) = 0;

	/** Controls the behaviour of the REGISTER command.
	 * @param rf The flags to set.
	 */
	virtual void SetRegisterFlags(uint8_t rf) = 0;

	/** Called when the result of an account registration has been ascertained.
	 * @param user The user who attempted to register na account.
	 * @param account The name of the account.
	 * @param code A code that tells the client what to do next.
	 * @param message A human-readable message to provide to the user.
	 */
	virtual void RegisterCallback(LocalUser* user, const std::string& account, const std::string& code, const std::string& message) = 0;

	/** Called when the result of an account verification has been ascertained.
	 * @param user The user who attempted to register na account.
	 * @param account The name of the account.
	 * @param message A human-readable message to provide to the user.
	 */
	virtual void VerifyCallback(LocalUser* user, const std::string& account, const std::string& message) = 0;
};

/** Allows modules to access information regarding user accounts. */
class Account::API final
	: public dynamic_reference<Account::APIBase>
{
public:
	API(Module* parent)
		: dynamic_reference<Account::APIBase>(parent, "accountapi")
	{
	}
};

/** Provides handlers for events relating to accounts. */
class Account::EventListener
	: public Events::ModuleEventListener
{
public:
	EventListener(Module* mod, unsigned int eventprio = DefaultPriority)
		: ModuleEventListener(mod, "event/account", eventprio)
	{
	}

	/** Called whenever a user logs in or out of an account.
	 * @param user The user who logged in or out.
	 * @param account The name of the account if logging in or empty if logging out.
	 */
	virtual void OnAccountChange(User* user, const std::string& account) = 0;
};

/** Defines the interface for the account provider API. */
class Account::ProviderAPIBase
	: public DataProvider
{
public:
	ProviderAPIBase(Module* mod)
		: DataProvider(mod, "accountproviderapi")
	{
	}

	virtual void Register(User* user, const std::string& account, const std::string& email, const std::string& password) = 0;
	virtual void Verify(User* user, const std::string& account, const std::string& code) = 0;
};

/** Allows modules to provide backend support for accounts. */
class Account::ProviderAPI final
	: public dynamic_reference<Account::ProviderAPIBase>
{
public:
	ProviderAPI(Module* mod)
		: dynamic_reference<Account::ProviderAPIBase>(mod, "accountproviderapi")
	{
	}
};
