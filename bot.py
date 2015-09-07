#! /usr/bin/env python

import hashlib
import binascii
import re
import pprint
pretty = pprint.PrettyPrinter(indent=2)

import client
import requests
import irc.client

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
    output = "\x02Now playing\x02: {} - {}".format(json.get('artist'), json.get('title'))
    if(json.get('WOAR') != None):
        output += " ( {} )".format(json['WOAR'])
    if(json.get('comment') != None and json['comment'] != "N/A" and json['comment'] != "NA"):
        output += " [{}]".format(json['comment'])
    bot.connection.privmsg(event.channel, output)

def format_size(size):
    ''' Literally explodes if someone returns content-length > 100TB '''
    prefixes = ['B', 'KB', 'MB', 'GB', 'TB']
    size = int(size)
    while size > 100:
        size = size/1024
        prefixes.pop(0)
    return "{0:.1f}".format(size)+prefixes.pop(0)

url_regex = re.compile(r'(https?|ftp)://[^\s/$.?#].[^\s]*', re.I)
title_regex = re.compile(r'<title>(.*?)</title>', re.I | re.U | re.M)
def url_peek(bot, event):
    print("Checking for url")
    matches = url_regex.search(event.arguments[0])
    print("I think my source is {} and my target is {}".format(event.source, event.target))
    if(matches != None):
        print("Trying to query '{}'".format(matches.group(0)))
        resp = requests.get(matches.group(0))
        if(resp.status_code != 200):
            bot.connection.privmsg(event.target, "[URL] Status code {}".format(resp.status_code))
            return
        content_type = resp.headers.get('content-type').split(';')[0] # Hack to trim shit out of content-type
        if(content_type == None or content_type == 'text/html'):
            title_match = title_regex.search(resp.text)
            if(title_match != None):
                bot.connection.privmsg(event.target, "[URL] {}".format(title_match.group(1)[0:80]))
            else:
                print("Failed to find a title for {}".format(event.arguments[0]))
        else:
            bot.connection.privmsg(event.target, "[{}] {}".format(content_type,format_size(resp.headers.get('content-length', 0))))
    else:
        print("No url found in '{}'".format(event.arguments[0]))

def get_playlist(bot, event):
	bot.connection.privmsg(event.channel, "Get the playlist at http://dj.toukufm.com:8000/touku.ogg.m3u")

def dump_meta(bot, event):
    r = requests.get('http://dj.toukufm.com:9090/getmeta')
    if(r.status_code != 200):
        bot.connection.privmsg(event.channel, "Failed to read now playing data :(")
        return
    json = r.json()
    pretty_json = pretty.pformat(json)
    for line in pretty_json.split('\n'):
        bot.connection.privmsg(event.source.nick, line)

if __name__ == '__main__':
    bot = client.BotClient()
    bot.admins = set()
    bot.add_irc_handler('welcome', join_channels)

    bot.add_cmd_handler('ident', identify_user)
    bot.add_irc_handler('part', unident_user)

    bot.add_cmd_handler('echo', echo_cmd)

    bot.add_cmd_handler('np', np_cmd)
    bot.add_cmd_handler('song', np_cmd)
    bot.add_cmd_handler('nowplaying', np_cmd)

    bot.add_cmd_handler('playlist', get_playlist)

    bot.add_cmd_handler('anime', lambda bot,event: bot.connection.privmsg(event.channel, "remember to say anime if your having a good time!"))

    bot.add_cmd_handler('allmeta', dump_meta)

    bot.add_irc_handler('pubmsg', url_peek)
    bot.connect()

