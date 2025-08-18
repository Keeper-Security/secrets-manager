# Update Set Commit History
This commit, and any commits following that contain the prefix [Historical Commit], were generated because 'Retain update set history as commits' was selected when this application was linked to Source Control. 
1. For every completed update set containing updates relevant to this application, commits have been generated automatically by the system. 
2. Updates are separated into multiple commits:
* if there are updates for a file that are out of order between different update sets
* if an update set contains multiple update records for a single file
The commits for an update set have been split into multiple commits ([Historical Commit 1], [Historical Commit 2]...) to represent each update. This is done so that each file has an in order history of updates. 
3. The most recent commit is the current state of your application in its entirety.

WARNING: Any commit prefixed by [Historical Commit] is generated solely to display its history. Do not attempt to check out these commits in the development process as they do not necessarily represent a stable snapshot of the application. 
See additional documentation: https://docs.servicenow.com/csh?topicname=migrate-update-set-history.html&version=latest