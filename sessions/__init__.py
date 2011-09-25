#!/usr/bin/env python
#
# Copyright 2011 Joseph Bowman 
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import functools
import uuid
import datetime
import settings
import time

class AsyncmongoSession(object):
    """
    AsyncmongoSession class, used to manage persistence across multiple requests. Uses
    a mongodb backend and Cookies. This library is designed for use with
    Tornado.

    Built on top of asyncmongo by bit.ly - https://github.com/bitly/asyncmongo
    The decorator is written to be completely asynchronous and not block.
    Because of this some care should be taken to optimize your MongoDB
    instance. Be sure to set an index on the "sid" key in your sessions
    collection.

    The session is added as session property to your request handler, ie:
    self.session. It can be manipulated as your would any dictionary object.

    Included with the library is a settings file, configured for default
    permissions. Some of the more advanced tuning you can do is with token
    expiration. In order to create some additional security for sessions used
    in a non-ssl environment, the token stored in the browser rotates. If you
    are using ssl, or more interested in performance than security you can set
    SESSION_TOKEN_TTL to an extremely high number to avoid writes.

    Note: In an effort increate performance, all writes are delayed until after the
    request method has completed. 

    Example:
        @amsession
        def get(self):
            self.render("index.html", session=self.session)
    """

    def __init__(self, req_obj,
            cookie_path=settings.session["DEFAULT_COOKIE_PATH"],
            cookie_name=settings.session["COOKIE_NAME"],
            set_cookie_expires=settings.session["SET_COOKIE_EXPIRES"],
            session_token_ttl=settings.session["SESSION_TOKEN_TTL"],
            session_expire_time=settings.session["SESSION_EXPIRE_TIME"],
            mongo_collection=settings.session["MONGO_COLLECTION"],
            callback=None):
        """
        __init__ loads the session, checking the browser for a valid session
        token. It will either validate the session and/or create a new one
        if necessary. db is the MongoDB connection which must be passed from
        the application.
        """

        self.req_obj = req_obj
        self.cookie_path = cookie_path
        self.cookie_name = cookie_name
        self.session_token_ttl = session_token_ttl
        self.session_expire_time = session_expire_time
        self.callback = callback
        self.db = req_obj.db[mongo_collection]

        self.new_session = True
        self.do_put = False
        self.do_save = False
        self.cookie = req_obj.get_cookie(cookie_name)
        if self.cookie:
            try:
                (self.token, self.sid) = self.cookie.split("@")
                self.session = self.db.find_one({"sid":
                    self.sid}, callback=self._validate_cookie)
            except:
                self._new_session()
        else:
            self._new_session()

    def _new_session(self):
        self.sid = str(uuid.uuid4())
        self.session = {"sid": self.sid,
                "tokens": [str(uuid.uuid4())],
                "last_token_update": datetime.datetime.now(),
                "data": {},
            }
        self._put()

    def _validate_cookie(self, response, error):
        if response:
            self.session = response
            if self.token in self.session["tokens"]:
                self.new_session = False
        if self.new_session:
            self._new_session()
        else:
            duration = datetime.timedelta(seconds=self.session_token_ttl)
            session_age_limit = datetime.datetime.now() - duration
            if self.session['last_token_update'] < session_age_limit:
                self.token = str(uuid.uuid4()) 
                if len(self.session['tokens']) > 2:
                    self.session['tokens'].pop(0)
                self.session['tokens'].insert(0,self.token)
                self.session["last_token_update"] = datetime.datetime.now()
                self.do_put = True

        if self.do_put:
            self._put()

    def _put(self):
        if self.session.get("_id"):
            self.db.update({"sid": self.sid}, {"$set": {"data":
                self.session["data"], "tokens": self.session["tokens"]}},
                callback=self._write_cookie)
        else:
            self.db.save(self.session, callback=self._write_cookie)

    def _write_cookie(self, *args, **kwargs):
        cookie = "%s@%s" % (self.session["tokens"][0], self.sid)
        self.req_obj.set_cookie(name = self.cookie_name, value =
                cookie, path = self.cookie_path)
        self.callback(self.req_obj)
        if self.do_save:
            self.db.update({"sid": self.sid}, {"$set": {"data":
            self.session["data"]}}, callback=self._pass)


    def delete(self):
        self.session['tokens'] = []
        self.do_save = True
        return True

    def has_key(self, keyname):
        return self.__contains__(keyname)

    def get(self, key, default):
        if self.has_key(key):
            return self[key]
        else:
            return default

    def __delitem__(self, key):
        del self.session["data"][key]
        self.do_save = True
        return True


    def __getitem__(self, key):
        return self.session["data"][key]

    def __setitem__(self, key, val):
        self.session["data"][key] = val
        self.do_save = True
        return True

    def __len__(self):
        return len(self.session["data"])

    def __contains__(self, key):
        return self.session["data"].has_key(key)

    def __iter__(self):
        for key in self.session["data"]:
            yield key

    def __str__(self):
        return u"{%s}" % ', '.join(['"%s" = "%s"' % (k, self.session["data"][k]) for k in self.session["data"]])

    def _pass(self, *args, **kwargs):
        pass

def amsession(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        self.session = AsyncmongoSession(self, callback=method)

    return wrapper 


