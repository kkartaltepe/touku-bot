#! /usr/bin/env python

import hashlib
import binascii
import functools
import re
import pprint
pretty = pprint.PrettyPrinter(indent=2)
import html

import client
import requests
import irc.client
from lxml import etree
import arrow

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
    # Fetch metadata
    r = requests.get('http://dj.toukufm.com:9090/getmeta')
    if(r.status_code != 200):
        bot.connection.privmsg(event.channel, "Failed to read now playing data :(")
        return
    json = r.json()

    # Fetch listener stats
    r = requests.get('http://dj.toukufm.com:8000/status-json.xsl')
    listeners = None
    if(r.status_code != 200):
        bot.connection.privmsg(event.channel, "Failed to read listener data :(")
    else:
        listeners = functools.reduce(lambda a,d: a+d['listeners'], r.json()['icestats']['source'], 0)

    output = "\x02Now playing\x02: {} - {}".format(json.get('artist'), json.get('title'))
    if(json.get('WOAR') != None):
        output += " ( {} )".format(json['WOAR'])
    if(json.get('comment') != None and json['comment'] != "N/A" and json['comment'] != "NA"):
        output += " [{}]".format(json['comment'])
    if(listeners != None):
        output += " with {} listeners.".format(listeners)
    bot.connection.privmsg(event.channel, output)

def next_show(bot, event):
    r = requests.get('http://toukufm.com/data/schedule')
    if(r.status_code != 200):
        bot.connection.privmsg(event.channel, "Failed to read schedule data :(")
        return
    json = r.json()['result']
    if(len(json) < 1):
        bot.connection.privmsg(event.channel, "No shows comming up soon. Check the schedule at http://toukufm.com/schedule for future shows")
        return

    json = json[0]
    show_time = arrow.get(json['start_unix'])
    now = arrow.now()
    if show_time < now:
        bot.connection.privmsg(event.channel, "Current show: {} by {} started {}".format(json['name'], json['host'], show_time.humanize(now)))
    else:
        bot.connection.privmsg(event.channel, "Next show: {} by {} in {}".format(json['name'], json['host'], show_time.humanize(now)))


def format_size(size):
    ''' Literally explodes if someone returns content-length > 100TB '''
    prefixes = ['B', 'KB', 'MB', 'GB', 'TB']
    size = int(size)
    while size > 100:
        size = size/1024
        prefixes.pop(0)
    return "{0:.1f}".format(size)+prefixes.pop(0)

url_regex = re.compile(r'(https?|ftp)://[^\s/$.?#].[^\s]*', re.I)
def url_peek(bot, event):
    matches = url_regex.search(event.arguments[0])
    if(matches != None):
        print("Trying to query '{}'".format(matches.group(0)))
        resp = requests.get(matches.group(0))
        resp.encoding = 'UTF-8'
        if(resp.status_code != 200):
            bot.connection.privmsg(event.target, "[URL] Status code {}".format(resp.status_code))
            return
        content_type = resp.headers.get('content-type').split(';')[0] # Hack to trim shit out of content-type
        if(content_type == None or content_type == 'text/html'):
            html_tree = etree.HTML(resp.text)
            title_match = html_tree.xpath("//title")
            if(len(title_match) > 0):
                title = html.unescape(title_match[0].text[0:80]);
                title = re.sub(r'\n', '', title) # Remove newlines before sending messages
                bot.connection.privmsg(event.target, "[URL] {}".format(title))
            else:
                print("Failed to find a title for {}".format(event.arguments[0]))
        else:
            bot.connection.privmsg(event.target, "[{}] {}".format(content_type,format_size(resp.headers.get('content-length', 0))))
    #else:
        #print("No url found in '{}'".format(event.arguments[0]))

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

def report_song(bot, event):
    r = requests.get('http://dj.toukufm.com:9090/getmeta')
    if(r.status_code != 200):
        bot.connection.privmsg(event.channel, "Failed to read now playing data :(")
        return
    json = r.json()
    admins = ['kurufu','shroo']
    for admin in admins:
        bot.connection.privmsg(admin, "{} reported [{}] for '{}'".format(event.source, json.get('track', "A DJ probably"), event.arguments))


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

    bot.add_cmd_handler('ns', next_show)
    bot.add_cmd_handler('nextshow', next_show)

    bot.add_cmd_handler('playlist', get_playlist)

    bot.add_cmd_handler('anime', lambda bot,event: bot.connection.privmsg(event.channel, "remember to say anime if your having a good time!"))

    bot.add_cmd_handler('allmeta', dump_meta)

    bot.add_cmd_handler('report', report_song)

    bot.add_irc_handler('pubmsg', url_peek)
    bot.connect()

