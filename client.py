import os

import irc.client
import yaml
from threading import Thread

class BotClient(object):

    def _load_config(location = './'):
        return yaml.load(open(os.path.join(location, 'config.yaml'), 'r'))

    def __init__(self):
        self.reactor = irc.client.Reactor()
        self.irc_handlers = {}
        self.cmd_handlers = {}
        self.add_irc_handler('disconnect', self._on_disconnect)
        self.add_irc_handler('all_raw_messages', self._log_all)
        self.add_irc_handler('ctcp', self._ctcp_version)
        self.config = BotClient._load_config()

    # Implement quering the server for information outside of event callbacks
    def _dispatch_irc_event(self, connection, event):
        if self.irc_handlers.get(event.type, None) != None:
            for handler in self.irc_handlers[event.type]:
                Thread(target=handler,args=(self,event)).start()
                #handler(self, event)

    def _dispatch_cmd_event(self, connection, event):
        # dont allow(fix) triggers for privmsg
        if irc.client.is_channel(event.target):
            # if there is no trigger proceed as everything might be a command
            if self.config.get('trigger', None) != None:
                # check trigger
                if event.arguments[0][0] == self.config['trigger']:
                    event.arguments[0] = event.arguments[0][1:] # Trim trigger
                # We are requiring a trigger to use cmds.
                else:
                    return
        event = self._parse_irc_event(event)
        if self.cmd_handlers.get(event.type, None):
            Thread(target=self.cmd_handlers[event.type], args=(self, event)).start()

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
            self.connection.ctcp_reply(event.source.nick, 'VERSION 420 SmokIRC erryday edition')

    def add_irc_handler(self, event_type, handler):
        if self.irc_handlers.get(event_type, None) == None:
            self.irc_handlers[event_type] = []
        self.irc_handlers[event_type].append(handler)

    def add_cmd_handler(self, cmd, handler):
        self.cmd_handlers[cmd] = handler;

    def connect(self, server = None, nick = None, port = 6667):
        server = self.config.get('server', server)    	
        nick = self.config.get('nick', nick)    	
        port = self.config.get('port', port)    	
        if(server == None):
            raise ValueError("Need a server value explicitly or in config")
        if(nick == None):
            raise ValueError("Need a nick value explicitly or in config")
	
        try:
            self.connection = self.reactor.server().connect(server, port, nick)
        except irc.client.ServerConnectionError:
            print(sys.exc_info()[1])
            raise SystemExit(1)

        self.connection.add_global_handler("all_events", self._dispatch_irc_event)
        self.connection.add_global_handler("privmsg", self._dispatch_cmd_event)
        self.connection.add_global_handler("pubmsg", self._dispatch_cmd_event)

        self.reactor.process_forever()

