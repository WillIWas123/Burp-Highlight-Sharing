# Highlight-Sharing

## What is this?

This is a small burp extension that allows teams to share their highlighting in burpsuite. This can be used to effeciently tell other team members who did what to avoid testing the same endpoints twice. Might also include sharing comments at a later point...


## How to use

Go to the Highlight-Sharing tab, enter the dbString, as well as the project name.

Workflow then becomes:

Work on an endpoint -> highlight the request -> right click

The reason you have to right click afterwards is a limitation from burp suite, I don't believe you can perform an action after the highlight is done...

## Setup

First you need to point burp to a jython standalone jar file. This can be done by going to Extender -> Options -> Python Environment -> Select file

Secondly you need to point burp to a mysql driver jar file, download this from [here](https://dev.mysql.com/downloads/connector/j/). Then go to Extender -> Options -> Java Environment -> Select folder, then select the folder the jar file is in.

Then you only need to go to Extensions -> Extensions -> Add, then choose the python file, and enjoy
