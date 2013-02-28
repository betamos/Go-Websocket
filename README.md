
Go-WebSocket
============

Implementation of the WebSocket protocol in [Go](http://golang.org/) according
to [RFC 6455](http://tools.ietf.org/html/rfc6455).
Others have done the same, they may be better or worse, I haven't looked at
them. I did this for the fun in following the RFC.

As a server
-----------

Currently this project aims at providing a well performing WebSocket server,
and it currently lacks client capabilities. Features include:

 * Multiple client connections, recieved asynchronously on a channel
 * Sending and recieving UTF-8 encoded messages

License
-------

Copyright (C) 2013 Didrik Nordström

This program is free software: you can redistribute it and/or modify it under
the terms of the [GNU General Public License version 3](http://www.gnu.org/licenses/gpl-3.0.html)
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
