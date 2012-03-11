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
import logging
import bson
from tornado.web import RequestHandler

class AsyncMongoSession(object):
    """
    AsyncmongoSession class, used to manage persistence across multiple requests. Uses
    a mongodb backend and Cookies. This library is designed for use with
    Tornado.

    Built on top of AsyncMongo by bit.ly - https://github.com/bitly/asyncmongo
    The decorator is written to be completely asynchronous and not block.

    The session is added as session property to your request handler, ie:
    self.session. It can be manipulated as your would any dictionary object.

    Included with the library is a settings file, configured for default
    permissions. Some of the more advanced tuning you can do is with token
    expiration. In order to create some additional security for sessions used
    in a non-ssl environment, the token stored in the browser rotates. If you
    are using ssl, or more interested in performance than security you can set
    SESSION_TOKEN_TTL to an extremely high number to avoid writes.

    Note: In an effort increate performance, all data writes are delayed until 
    after the request method has completed. However, security token updates
    are saved as they happen.

    Example:
        @asynmongosession
        def get(self):
            if self.session.has_key("test"):
                self.session += 1
            else:
                self.session = 0
            self.render("index.html", session=self.session)
    """

    def __init__(self, req_obj,
            cookie_path=settings.session["DEFAULT_COOKIE_PATH"],
            cookie_name=settings.session["COOKIE_NAME"],
            set_cookie_expires=settings.session["SET_COOKIE_EXPIRES"],
            session_token_ttl=settings.session["SESSION_TOKEN_TTL"],
            session_expire_time=settings.session["SESSION_EXPIRE_TIME"],
            mongo_collection=settings.session["MONGO_COLLECTION"],
            db=None,
            callback=None):
        """
        __init__ loads the session, checking the browser for a valid session
        token. It will either validate the session and/or create a new one
        if necessary. 
        
        The db object should be a mongodb database, not collection. The
        collection value is set by the settings for the library. See
        settings.py for more information.

        If you already have a db attribute on the request or application
        objects then there is no need to pass it. Sessions will automatically
        check those objects for a valid database object to use.
        """
        self.req_obj = req_obj
        self.cookie_path = cookie_path
        self.cookie_name = cookie_name
        self.session_token_ttl = session_token_ttl
        self.session_expire_time = session_expire_time
        self.callback = callback
        if db:
            self.db = db[mongo_collection]
        elif hasattr(self.req_obj, "db"):
            self.db = self.req_obj.db[mongo_collection]
        elif hasattr(self.req_obj.application, "db"):
            self.db = self.req_obj.application.db[mongo_collection]
        else:
            raise ValueError("Invalid value for db")

        self.new_session = True
        self.do_put = False
        self.do_save = False
        self.do_delete = False
        self.cookie = self.req_obj.get_secure_cookie(cookie_name)

        if self.cookie:
            (self.token, _id) = self.cookie.split("@")
            self.session = self.db.find_one({"_id":
                bson.ObjectId(_id)}, callback=self._validate_cookie)
        else:
            self._new_session()

    def _new_session(self):
        self.session = {"_id": bson.ObjectId(),
                "tokens": [str(uuid.uuid4())],
                "last_token_update": datetime.datetime.utcnow(),
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
            session_age_limit = datetime.datetime.utcnow() - duration
            if self.session['last_token_update'] < session_age_limit:
                self.token = str(uuid.uuid4()) 
                if len(self.session['tokens']) > 2:
                    self.session['tokens'].pop(0)
                self.session['tokens'].insert(0,self.token)
                self.session["last_token_update"] = datetime.datetime.utcnow()
                self.do_put = True

            if self.do_put:
                self._put()
            else:
                self._handle_response()

    def _put(self):
        if self.session.get("_id"):
            self.db.update({"_id": self.session["_id"]}, {"$set": {"data":
                self.session["data"], "tokens": self.session["tokens"],
                "last_token_update": self.session["last_token_update"]}},
                upsert=True,
                callback=self._handle_response)
        else:
            self.db.save(self.session, callback=self._handle_response)

    def _handle_response(self, *args, **kwargs):
        cookie = "%s@%s" % (self.session["tokens"][0], self.session["_id"])
        self.req_obj.set_secure_cookie(name = self.cookie_name, value =
                cookie, path = self.cookie_path)
        self.callback(self.req_obj)

    def get_token(self):
        return self.cookie

    def get_id(self):
        return self.session.get("_id")

    def delete(self):
        self.session['tokens'] = []
        self.do_delete = True
        return True

    def has_key(self, keyname):
        return self.__contains__(keyname)

    def get(self, key, default=None):
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

    def _pass(self, response, error):
        pass

def asyncmongosession(method):

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        def finish(self, *args, **kwargs):
            """ 
            This is a monkey patch finish which will save or delete
            session data at the end of a request.
            """
            super(self.__class__, self).finish(*args, **kwargs)
            if self.session.do_save:
                self.session.db.update({"_id": self.session.session["_id"]}, {"$set": {"data":
                self.session.session["data"]}}, callback=self.session._pass)
            if self.session.do_delete:
                self.session.db.remove({"_id": self.session.session["_id"]},
                        callback=self.session._pass)

        self.finish = functools.partial(finish, self)
        self.session = AsyncMongoSession(self, callback=method)

    return wrapper 

