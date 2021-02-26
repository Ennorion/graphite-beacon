# -*- coding: utf-8 -*-
import json
import socket
import time

from graphite_beacon.handlers import LOGGER, AbstractHandler
from tornado import gen


class SensuHandler(AbstractHandler):

    name = 'sensu'

    OK = 0
    WARNING = 1
    ERROR = 2
    UNKNOWN = 3

    defaults = {
        'address': 'localhost',
        'port': 3030,
        'source': 'Graphite_Beacon',
        'handlers': ['default'],
        'ttl': 600
    }

    def init_handler(self):
        self.address = self.options['address']
        self.port = self.options['port']
        self.source = self.options['source']
        self.handlers = self.options['handlers']
        self.ttl = self.options['ttl']

    def __send(self, message):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((self.address, self.port))
            s.send(message.encode())
        except Exception as e:
            LOGGER.error("Cannot send alert with error: %s", e)

    def __compose(self, output, status):
        alert_name = output.rsplit(' ')[0]
        alert_name = str(alert_name).rsplit(' ', 1)[0].strip()
        message = {
            'name': alert_name,
            'issued': int(time.time()),
            'output': output.strip(),
            'status': status,
            'handlers': self.handlers,
            'source': self.source
        }
        return json.dumps(message)

    def ok(self, message):
        self.__send(self.__compose(message, self.OK))

    def warning(self, message):
        self.__send(self.__compose(message, self.WARNING))

    def error(self, message):
        self.__send(self.__compose(message, self.ERROR))

    def unknown(self, message):
        self.__send(self.__compose(message, self.UNKNOWN))

    @gen.coroutine
    def notify(self, level, alert, value, target=None, **kwargs):
        LOGGER.debug("Handler (%s) %s", self.name, level)

        rule = kwargs.get('rule', {})
        operator = dict(rule.get('exprs', '')[0]).get('op')
        operator = str(operator).split(' ')[2].rstrip('>')
        rule_value = dict(rule.get('exprs', '')[0]).get('value')
        status = str(level).upper()
        output = '{0} {1}: {2} [{3}] | {4} {5}'.format(alert, status, value,
                                                       target, operator, rule_value)
        if level == 'critical':
            self.error(output)
        elif level == 'warning':
            self.warning(output)
        elif level == 'normal':
            self.ok(output)
        else:
            self.unknown('unknown response')
