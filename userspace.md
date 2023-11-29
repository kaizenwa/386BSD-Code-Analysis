## Walkthrough of FreeBSD 1's _init_ Process

Since I cannot locate the init source file for 386BSD 0.1, I will be
using FreeBSD 1's init source file instead. I am assuming that they
are pretty much the same thing since the init source file has nothing
to do with underlying hardware.

### Contents

1. Code Flow
2. Source Code Commentary (Single-user Mode)
3. Source Code Commentary (Multi-user Mode)

### Code Flow

#### Single-user Mode

```txt
main
    setsid
    revoke
    login_tty
    execl
```

#### Multi-user Mode

```txt
```

### Source Code Commentary (Single-user Mode)

#### main (freebsd-1.0/sbin/init/init.c:151)

```txt
167: Calls setsid.

229: Child calls revoke on /dev/console.

232: Child calls login_tty on /dev/console.

233: Child calls execl on /bin/sh.

236: Parent calls wait.
```

#### setsid (386bsd-0.1/sys/kern/kern\_prot.c:172)

```txt
Control Flow:
main
    setsid <-- Here
```

#### revoke (386bsd-0.1/sys/kern/vfs\_syscalls.c:1741)

```txt
Control Flow:
main
    setsid
    revoke <-- Here (child)
```

#### login\_tty (386bsd-0.1/usr/src/lib/libutil/login\_tty.c:41)

```txt
Control Flow:
main
    setsid
    revoke
    login_tty <-- Here (child)

44: Calls setsid.

45: Calls ioctl on /dev/console to set it as the controlling terminal.

47-49: Calls dup2 to create STDIN, STDOUT, and STDERR.
```

#### ioctl (386bsd-0.1/sys/kern/sys\_generic.c:346)

```txt
Control Flow:
main
    setsid
    revoke
    login_tty
        ioctl <-- Here (child)

462: Calls ttioctl.
```

#### ttioctl (386bsd-0.1/sys/kern/tty.c:284)

```txt
Control Flow:
main
    setsid
    revoke
    login_tty
        ioctl
            ttioctl <-- Here (child)
```

#### execl (/usr/src/lib/libc/gen/exec.c:86)

```txt
Control Flow:
main
    setsid
    revoke
    login_tty
    execl <-- Here (child)
```

#### wait (/usr/src/lib/libc/gen/wait.c:44)

```txt
Control Flow:
main
    setsid
    wait <-- (parent)
```

### Source Code Commentary (Multi-user Mode)

#### main (freebsd-1.0/sbin/init/init.c:151) 

```txt
167: Calls setsid.

191: Calls saccess on /etc/rc.

201: Child calls revoke on /dev/console.

204: Child calls login_tty on /dev/console.

205: Child calls execl on /bin/sh, passing /etc/rc as an
     argument.

206: Calls _exit.

208: Parent sets Reboot to zero.

209: Parent calls wait.

212-213: Parent calls pause if the child received SIGKILL.

214: Parent calls logwtmp.

243: Parent calls setttyent.

244-248: Initializes the entries in the ttytab (line 81) using /etc/ttys.

250: Assigns the current value of tt to ttyabend.

251: Calls endttyent.

252: Calls getty for each entry in the ttytab.
```

#### setsid (386bsd-0.1/sys/kern/kern\_prot.c:172)

```txt
Control Flow:
main
    setsid <-- Here
```

#### saccess (386bsd-0.1/sys/kern/vfs\_syscalls.c:973)

```txt
Control Flow:
main
    setsid
    saccess <-- Here (child)
```

#### revoke (386bsd-0.1/sys/kern/vfs\_syscalls.c:1741)

```txt
Control Flow:
main
    setsid
    revoke <-- Here (child)
```

#### login\_tty (386bsd-0.1/usr/src/lib/libutil/login\_tty.c:41)

```txt
Control Flow:
main
    setsid
    revoke
    login_tty <-- Here (child)
```

#### execl (386bsd-0.1/usr/src/lib/libc/gen/exec.c:86)

```txt
Control Flow:
main
    setsid
    revoke
    login_tty
    execl <-- Here (child)
```

#### rc (freebsd-1.0/etc/rc:10)

```txt
17: Exports root directory as HOME variable.

18-19: Exports /sbin:/bin:/usr/sbin:/usr/bin as the PATH variable.

79-82: Runs /etc/rc.serial scrip to configure serial devices.

86: Runs /etc/netstart to turn on the network.


```

#### setttyent (386bsd-0.1/usr/src/lib/libc/gen/getttyent.c:177)

```txt
Control Flow:
main
    setsid
    setttyent <-- Here (parent)


181: Calls rewind if tf already points to a file.

183: Calls fopen to open /etc/ttys as a read-only file.
```

#### endttyent (/386bsd-0.1/usr/src/lib/libc/gen/getttyent.c:189)

```txt
Control Flow:
main
    setsid
    setttyent
    gettyent
    endttyent <-- Here (parent)

193-197: Calls fclose on tf if it points to a file and returns rval.
```

#### getty (freebsd-1.0/libexec/getty/main.c:137)

```txt
Control Flow:
main
    setsid
    setttyent
    getttyent
    endttyent
    getty <-- Here (parent)

237: Calls getname.

255: Calls execle to create a login shell for the user.
```

#### getname (386bsd-0.1/usr/src/libexec/getty/main.c:288)

```txt
Control Flow:
main
    setsid
    setttyent
    getttyent
    endttyent
    getty
        getname <-- Here (parent)
```
