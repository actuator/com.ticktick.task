# TickTick Android Dirty Stream Path Traversal via Unsanitized Attachment Filename

**Vendor:** TickTick  
**Product:** TickTick Android (`com.ticktick.task`)  
**Affected Version:** 8.2.2.0
**Vulnerability Type:** Path Traversal / Dirty Stream  
**CWE:** CWE-22 – Improper Limitation of a Pathname to a Restricted Directory  
**Attack Vector:** Local, malicious Android application  
**Authentication:** Not required  
**User Interaction:** No additional interaction after the crafted share intent is processed (pending runtime confirmation)

<img width="1193" height="692" alt="image" src="https://github.com/actuator/com.ticktick.task/blob/main/%20com.ticktick.task-PAthTrav-DS.gif" />

### Vulnerability Description

TickTick Android version 8.2.2.0 contains a  Dirty Stream path traversal vulnerability in its attachment import functionality.

The exported `ShareReceiveActivity` accepts externally supplied `content://` URIs through `ACTION_SEND` and `ACTION_SEND_MULTIPLE` intents without requiring a privileged permission.

During attachment processing, `FileManager.getDisplayNameFromUri()` obtains the attacker-controlled `_display_name` from the supplied ContentProvider. The filename is subsequently passed to `AttachmentFileHelper.copyFileDirectly()` without adequate path sanitization.

Because the filename is used to construct a filesystem path without enforcing that the destination remains inside the intended attachment directory, traversal sequences such as `../` may permit an attacker-controlled application to write files outside that directory using TickTick's application privileges.

Static analysis indicates that attachment copying is initiated automatically during share editor initialization, without requiring the user to save the task.

### Affected Components

- `com.ticktick.task.activity.ShareReceiveActivity`
- `TaskViewFragment.initShareAndNoteToSelfTask`
- `FileManager.pickFiles`
- `FileManager.getDisplayNameFromUri`
- `AttachmentFileHelper.copyFileDirectly`

### Proof of Concept

A malicious Android ContentProvider returns the following values:

**Content URI:**
`content://com.poc.ttds.evil/poc.bin`

**Attacker-controlled `_display_name`:**
`../PWNED_TT.txt`

The PoC delivers this URI to TickTick's exported share receiver using an Android `ACTION_SEND` intent.

The supplied file content is a harmless marker identifying the Dirty Stream test.

If the vulnerable copy operation executes as identified during static analysis, the traversal causes the file to be written outside the intended attachment subdirectory.

### Security Impact

Successful exploitation could allow an unprivileged malicious application to create or overwrite files accessible to TickTick outside its intended attachment directory.

### Validation Status

The vulnerable filename-handling path has been identified through Dynamic and static analysis
