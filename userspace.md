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

#### main (/sbin/init/init.c:151)

```txt
167: Calls setsid.

229: Child calls revoke on /dev/console.

232: Child calls login_tty on /dev/console.

233: Child calls execl on /bin/sh.

236: Parent calls wait.
```

#### setsid (/sys/kern/kern\_prot.c:172)

```txt
Control Flow:
main
    setsid <-- Here
```

#### revoke (/sys/kern/vfs\_syscalls.c:1741)

```txt
Control Flow:
main
    setsid
    revoke <-- Here (child)
```

#### login\_tty (/usr/src/lib/libutil/login\_tty.c:41)

```txt
Control Flow:
main
    setsid
    revoke
    login_tty <-- Here (child)
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

#### main (/sbin/init/init.c:151) 

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


```

#### setsid (/sys/kern/kern\_prot.c:172)

```txt
Control Flow:
main
    setsid <-- Here
```

#### saccess (/sys/kern/vfs\_syscalls.c:973)

```txt
Control Flow:
main
    setsid
    saccess <-- Here (child)
```

#### revoke (/sys/kern/vfs\_syscalls.c:1741)

```txt
Control Flow:
main
    setsid
    revoke <-- Here (child)
```

#### login\_tty (/usr/src/lib/libutil/login\_tty.c:41)

```txt
Control Flow:
main
    setsid
    revoke
    login_tty <-- Here (child)
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

#### rc (freebsd-1.0/etc/rc:10)

```txt
17: Exports root directory as HOME variable.

18-19: Exports /sbin:/bin:/usr/sbin:/usr/bin as the PATH variable.

79-82: Runs /etc/rc.serial scrip to configure serial devices.

86: Runs /etc/netstart to turn on the network.


```

#### setttyent (/usr/src/lib/libc/gen/getttyent.c:177)

```txt
Control Flow:
main
    setsid
    setttyent <-- Here (parent)
```
