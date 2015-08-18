#! /usr/bin/env python

import sys
import argparse
import hashlib
import binascii

import irc.client
import yaml
import os

class BotClient(object):

    def __init__(self):
        self.reactor = irc.client.Reactor()
        self.irc_handlers = {}
        self.cmd_handlers = {}
        self.add_irc_handler('disconnect', self._on_disconnect)
        self.add_irc_handler('all_raw_messages', self._log_all)
        self.add_irc_handler('ctcp', self._ctcp_version)

    # Implement quering the server for information outside of event callbacks

    def _dispatch_irc_event(self, connection, event):
        if self.irc_handlers.get(event.type, None) != None:
            for handler in self.irc_handlers[event.type]:
                handler(self, event)

    def _dispatch_cmd_event(self, connection, event):
        # dont allow(fix) triggers for privmsg
        if irc.client.is_channel(event.target):
            # if there is no trigger proceed as everything might be a command
            if bot.config.get('trigger', None) != None:
                # check trigger
                if event.arguments[0][0] == bot.config.get['trigger']:
                    event.arguments[0] = event.arguments[0][1:] # Trim trigger
                # We are requiring a trigger to use cmds.
                else:
                    return
        event = self._parse_irc_event(event)
        if self.cmd_handlers.get(event.type, None):
            self.cmd_handlers[event.type](self, event)

    def _parse_irc_event(self, event):
        split = event.arguments[0].split(' ', 1)
        irc_cmd, irc_args = None, None
        if len(split) < 2:
            irc_cmd = split[0]
        else:
            irc_cmd, irc_args = split

        # "channel" if this message was directed to a channel, otherwise the place to reply to.
        if irc.client.is_channel(event.target):
            event.channel = event.target
        else:
            event.channel = event.source.nick
        event.type = irc_cmd
        event.arguments = irc_args
        return event

    def _on_disconnect(self, bot, event):
        self.reconnect()

    def _log_all(self, bot, event):
        print('({0.source}) {0.arguments[0]}'.format(event))

    def _ctcp_version(self, bot, event):
        ''' Handle the CTCP VERSION request, hardcoded for now '''
        if event.arguments[0] == 'VERSION':
            bot.connection.ctcp_reply(event.source.nick, 'VERSION 420 SmokIRC erryday edition')

    def add_irc_handler(self, event_type, handler):
        if self.irc_handlers.get(event_type, None) == None:
            self.irc_handlers[event_type] = []
        self.irc_handlers[event_type].append(handler)

    def add_cmd_handler(self, cmd, handler):
        self.cmd_handlers[cmd] = handler;

    def connect(self, server, nick, port = 6667):
        try:
            self.connection = self.reactor.server().connect(server, port, nick)
        except irc.client.ServerConnectionError:
            print(sys.exc_info()[1])
            raise SystemExit(1)

        self.connection.add_global_handler("all_events", self._dispatch_irc_event)
        self.connection.add_global_handler("privmsg", self._dispatch_cmd_event)
        self.connection.add_global_handler("pubmsg", self._dispatch_cmd_event)

        self.reactor.process_forever()

def load_config(location = './'):
    return yaml.load(open(os.path.join(location, 'config.yaml'), 'r'))

def join_channels(bot, event):
    for channel in bot.config['channels']:
        bot.connection.join(channel)

def identify_user(bot, event):
    '''
    Allows admins to authenticate with the bot via their predefined passwords
    Passwords in the config file are hashed and salted (consider storing salt
    instead of 1 salt for all passwords (lel using 1 salt). Users are identified by
    their fully qualified nick, user, host and only for the period of time they are
    in the channel.

    You cannot identify if you are not currently in a channel occupied by the bot.
    this is to prevent impersonation attacks where the bot doesnt see you leave.
    '''
    if irc.client.is_channel(event.channel):
        bot.connection.privmsg(event.channel, "You know better than to ident in a public channel dont you?")
        return
    user = event.source
    # UTF-8 decoding by default python 3.4
    pass_hash = hashlib.pbkdf2_hmac('sha256', bytearray(event.arguments, 'UTF-8'), b'This is our current salt', 1000)
    pass_hash = binascii.hexlify(pass_hash).decode()
    print("Generated password hash '{0}' => '{1}'".format(event.arguments, pass_hash))
    admin_passes = bot.config.get('admin_passes', None)
    if admin_passes == None:
        bot.connection.privmsg(user.nick, "No admins defined for this bot")
        return

    if admin_passes.get(user, None) == None:
        print("Non-admin user tried authenticating")
        bot.connection.privmsg(user.nick, "Authentication Failed")
        return

    if admin_passes[user] != pass_hash:
        print("Admin user failed to authenticate: {0} with {1}, expected {2}".format(user, pass_hash, admin_passes[user]))
        bot.connection.privmsg(user.nick, "Authentication Failed")
        return

    if admin_passes[user] == pass_hash:
        #Consider making this not an explicit if, but hey security!
        bot.admins.add(user)
        print(bot.admins)
        bot.connection.privmsg(user.nick, "Authentication Successful")

def unident_user(bot, event):
    user = event.source
    if user in bot.admins:
        print("Deauthorizing {}".format(user))
        bot.admins.remove(user)

def echo_cmd(bot, event):
    if event.source not in bot.admins:
        return
    bot.connection.privmsg(event.channel, event.arguments)

if __name__ == '__main__':
    bot = BotClient()
    config = load_config()
    print(config)
    bot.config = config
    bot.admins = set()
    bot.add_irc_handler('welcome', join_channels)

    bot.add_cmd_handler('ident', identify_user)
    bot.add_irc_handler('part', unident_user)

    bot.add_cmd_handler('echo', echo_cmd)

    bot.connect(config['server'], config['nick'], config['port'])

