#! /usr/bin/env python

import hashlib
import binascii

import client
import requests

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

    admin_passes = bot.config.get('admin_passes', None)
    if admin_passes == None:
        bot.connection.privmsg(user.nick, "No admins defined for this bot")
        return

    if admin_passes.get(user, None) == None:
        print("Non-admin user tried authenticating")
        bot.connection.privmsg(user.nick, "Authentication Failed")
        return

    # UTF-8 decoding by default python 3.4
    pass_hash = hashlib.pbkdf2_hmac('sha256', \
            bytearray(event.arguments, 'UTF-8'), \
            binascii.unhexlify(admin_passes[user]['salt']), \
            1000)
    pass_hash = binascii.hexlify(pass_hash).decode()
    # print("Generated password hash '{0}' => '{1}'".format(event.arguments, pass_hash))

    if admin_passes[user]['passwd'] != pass_hash:
        print("Admin user failed to authenticate: {0} with {1}, expected {2}".format(user, pass_hash, admin_passes[user]['passwd']))
        bot.connection.privmsg(user.nick, "Authentication Failed")
        return

    if admin_passes[user]['passwd'] == pass_hash:
        #Consider making this not an explicit if, but hey security!
        bot.admins.add(user)
        print("{0} Successfully authenticated".format(user))
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

def np_cmd(bot, event):
    r = requests.get('http://dj.toukufm.com:9090/getmeta')	
    if(r.status_code != 200):
        bot.connection.privmsg(event.channel, "Failed to read now playing data :(")
        return
    json = r.json()
    bot.connection.privmsg(event.channel, "Now playing {} - {}".format(json['artist'], json['title']))

if __name__ == '__main__':
    bot = client.BotClient()
    bot.admins = set()
    bot.add_irc_handler('welcome', join_channels)

    bot.add_cmd_handler('ident', identify_user)
    bot.add_irc_handler('part', unident_user)

    bot.add_cmd_handler('echo', echo_cmd)

    bot.add_cmd_handler('np', np_cmd)
    bot.add_cmd_handler('song', np_cmd)

    bot.connect()

