/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2026 Sadie Powell <sadie@witchery.services>
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

#include "utils.h"
#include "commands.h"
#include "remoteuser.h"

CmdResult CommandReply::HandleServer(TreeServer* server, CommandBase::Params& params)
{
	// <source-sid> <target-uuid> <command> <code> [<params>] :<message>
	auto* target = ServerInstance->Users.FindUUID(params[1]);
	if (!target)
		return CmdResult::FAILURE; // User has gone.

	auto* ltarget = IS_LOCAL(target);
	if (!ltarget)
		return CmdResult::SUCCESS; // Not for us.

	Command* cmd = nullptr;
	if (params[2] != "*")
		cmd = ServerInstance->Parser.GetHandler(params[2]);

	const auto* source = Utils->FindServerID(params[0]);
	ClientProtocol::Message msg(this->name.c_str(), source ? source->ServerUser : nullptr);
	if (cmd)
		msg.PushParamRef(cmd->name);
	else
		msg.PushParam("*");
	msg.PushParam(params[3]);
	for (auto it = params.begin() + 4; it != params.end(); ++it)
		msg.PushParam(*it);

	ClientProtocol::Event ev(evprov, msg);
	ltarget->Send(ev);

	return CmdResult::SUCCESS;
}

RouteDescriptor CommandReply::GetRouting(User* user, const Params& params)
{
	return ROUTE_OPT_UCAST(params[1]);
}
