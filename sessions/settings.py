#!/usr/bin/env python
#
# Copyright 2009 unscatter.com
#
# This source code is proprietary and owned by jbowman and may not
# be copied, distributed, or run without prior permission from the owner.

__author__="bowman.joseph@gmail.com"
__date__ ="$September 24, 2011 1:50:35 PM$"


session = {
    "COOKIE_NAME": "asyncmongo_session",
    "DEFAULT_COOKIE_PATH": "/",
    "SESSION_EXPIRE_TIME": 7200,    # sessions are valid for 7200 seconds
                                    # (2 hours)
    "SET_COOKIE_EXPIRES": True,     # Set to True to add expiration field to
                                    # cookie
    "SESSION_TOKEN_TTL": 5,         # Number of seconds a session token is valid
                                    # for.
    "UPDATE_LAST_ACTIVITY": 60,     # Number of seconds that may pass before
                                    # last_activity is updated
    "MONGO_COLLECTION": 'sessions',
    "MONGO_COLLECTION_SIZE": 100000,
}
