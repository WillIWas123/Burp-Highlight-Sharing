# Highlight-Sharing

## DISCLAIMER

This is untested software, don't expect this to be bug-free yet. 

## What is this?

This is a small burp extension that allows teams to share their highlighting in burpsuite. This can be used to effeciently tell other team members who did what to avoid testing the same endpoints twice.


## How to use

Go to the Highlight-Sharing tab, enter a username, the websocket string (currently does not support SSL), as well as the project name.

the websocket string may look something like: ws://localhost:8000/

When connecting to the server the server will automatically update you on highlights and comments. If a team member highlighted a request you didn't have, you can get the highlight be reconnecting...

Workflow then becomes:

Work on an endpoint -> highlight the request (Too efficiently highlight requests I suggest creating a shortcut) -> right click

The reason you have to right click afterwards is a limitation from burp suite, I don't believe you can perform an action after the highlight is done, but you can do stuff whenever a menu is created...


## Setup

You need the server to be running somewhere, in the docker folder you can see a readme on how to set that up.

You need to point burp to a jython standalone jar file. This can be done by going to Extender -> Options -> Python Environment -> Select file

Then you only need to go to Extensions -> Extensions -> Add, then choose the python file, and enjoy
