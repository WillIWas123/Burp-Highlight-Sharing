# Highlight-Sharing

## What is this?

This is a small burp extension that allows teams to share their highlighting in burpsuite. This can be used to effeciently tell other team members who did what to avoid testing the same endpoints twice.


## How to use

Go to the Highlight-Sharing tab, enter the dbString, as well as the project name.

When connecting to the server the server will automatically update you on highlights and comments, if a team member highlighted a request you didn't have, you can get the highlight be reconnecting...

Workflow then becomes:

Work on an endpoint -> highlight the request -> right click

The reason you have to right click afterwards is a limitation from burp suite, I don't believe you can perform an action after the highlight is done...


## Setup

First you need to point burp to a jython standalone jar file. This can be done by going to Extender -> Options -> Python Environment -> Select file

Then you only need to go to Extensions -> Extensions -> Add, then choose the python file, and enjoy
