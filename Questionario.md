**Questionário de Preparação RHCSA EX200 (RHEL 9.3)**

Este documento reúne **30 tarefas práticas** no estilo da prova **RHCSA EX200**.  
Cada questão contém o **enunciado** e a **resposta esperada** com comandos que devem ser aplicados no RHEL 9.3.

Use este material como apoio no estudo individual.

---
## 🔹Storage, Filesystem & LVM

### 1) Criar PV/VG/LV, formatar XFS e montar em /dados com fstab
```bash
sudo pvcreate /dev/vdb
sudo vgcreate vgdados /dev/vdb
sudo lvcreate -L 4G -n lvapp vgdados
sudo mkfs.xfs /dev/vgdados/lvapp
sudo mkdir -p /dados
echo "/dev/vgdados/lvapp /dados xfs defaults 0 0" | sudo tee -a /etc/fstab
sudo mount -a && findmnt /dados
```
##

### 2) Expandir LV para 6G e crescer XFS online

```bash
sudo lvextend -L 6G /dev/vgdados/lvapp
sudo xfs_growfs /dados
```

### 3) Criar snapshot LVM de 1G

```bash
sudo lvcreate -s -L 1G -n lvapp_snap /dev/vgdados/lvapp
sudo lvs
```

### 4) Converter partição para PV adicional e estender VG

```bash
sudo pvcreate /dev/vdc
sudo vgextend vgdados /dev/vdc
sudo vgs
```

### 5) Criar subdiretório com quota de projeto XFS

```bash
sudo mount -o remount,prjquota /dados
sudo mkdir -p /dados/projetos
echo "1001:/dados/projetos" | sudo tee -a /etc/projects
echo "projA:1001" | sudo tee -a /etc/projid
sudo xfs_quota -x -c 'project -s projA' /dados
sudo xfs_quota -x -c 'limit -p bsoft=450m bhard=500m projA' /dados
```

### 6) Criar filesystem ext4 e montar com opções noexec,nodev,nosuid

```bash
sudo mkfs.ext4 /dev/vdd1
sudo mkdir -p /seguro
echo "/dev/vdd1 /seguro ext4 defaults,noexec,nodev,nosuid 0 0" | sudo tee -a /etc/fstab
sudo mount -a && findmnt /seguro
```

### 7) Diagnosticar ponto de montagem quebrado via fstab

```bash
sudo mount -a 2>&1 | tee /tmp/mount.err
grep /dados /etc/fstab
# corrigir linha incorreta e rodar novamente:
sudo mount -a
```

---

## 🔹 Permissões, ACLs, umask

### 8) Diretório colaborativo com SGID e ACL default

```bash
sudo mkdir -p /srv/colab
sudo chgrp devs /srv/colab
sudo chmod 2775 /srv/colab
sudo setfacl -m d:g:devs:rwx /srv/colab
```

### 9) Definir umask global 027

```bash
echo 'umask 027' | sudo tee /etc/profile.d/umask.sh
```

### 10) SUID/SGID em utilitário custom

```bash
sudo cp /usr/bin/true /usr/local/bin/elevado
sudo chown root:root /usr/local/bin/elevado
sudo chmod 4755 /usr/local/bin/elevado
```

---

## 🔹 Usuários, Grupos & SSH

### 11) Criar usuário com grupo suplementar e expiração

```bash
sudo useradd -m -s /bin/bash -G devs -e 2030-12-31 ana
sudo passwd ana
sudo chage -l ana
```

### 12) Bloquear login de root e desabilitar senha no SSH

```bash
sudo sed -ri 's/^[# ]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -ri 's/^[# ]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### 13) Chave pública para usuário e teste de login local

```bash
sudo -iu ana ssh-keygen -q -N "" -f ~/.ssh/id_ed25519
sudo -iu ana mkdir -p ~/.ssh && chmod 700 ~/.ssh
sudo -iu ana cp ~/.ssh/id_ed25519.pub ~/.ssh/authorized_keys
sudo -iu ana chmod 600 ~/.ssh/authorized_keys
sudo -iu ana ssh -o StrictHostKeyChecking=no localhost 'echo ok'
```

---

## 🔹 SELinux

### 14) Fcontext e boolean httpd\_can\_network\_connect

```bash
sudo semanage fcontext -a -t httpd_sys_content_t "/srv/www(/.*)?"
sudo restorecon -RFv /srv/www
sudo setsebool -P httpd_can_network_connect on
```

### 15) Colocar SELinux em Enforcing e persistir

```bash
sudo setenforce 1
sudo sed -ri 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
```

### 16) Identificar e explicar um AVC recente

```bash
sudo ausearch -m AVC -ts recent | sudo sealert -a -
```

---

## 🔹 Rede & Hostname

### 17) Criar conexão estática com nmcli

```bash
sudo nmcli con add type ethernet con-name lab-static ifname eth0 \
  ipv4.method manual ipv4.addresses 192.168.50.10/24 \
  ipv4.gateway 192.168.50.1 ipv4.dns 1.1.1.1
sudo nmcli con up lab-static
```

### 18) Definir hostname FQDN

```bash
sudo hostnamectl set-hostname lab.example.com
hostname -f
```

---

## 🔹 Firewalld

### 19) Permitir HTTP e porta 8080/tcp permanentemente

```bash
sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

### 20) Criar rich rule para permitir 10.10.10.0/24 em 22/tcp

```bash
sudo firewall-cmd --permanent \
  --add-rich-rule='rule family="ipv4" source address="10.10.10.0/24" port protocol="tcp" port="22" accept'
sudo firewall-cmd --reload
```

---

## 🔹 NTP/Chrony & Journald

### 21) Habilitar chrony e confirmar fontes

```bash
sudo systemctl enable --now chronyd
chronyc tracking
chronyc sources -v
```

### 22) Tornar o Journald persistente

```bash
echo 'Storage=persistent' | sudo tee -a /etc/systemd/journald.conf
sudo mkdir -p /var/log/journal
sudo systemctl restart systemd-journald
```

---

## 🔹 Systemctl

### 23) Ativar IP forwarding em runtime e persistência

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-sysctl.conf
sudo sysctl --system | grep net.ipv4.ip_forward
```

---

## 🔹 Systemd & Cron

### 24) Criar service e timer para backup diário 02:00

```bash
echo -e '#!/usr/bin/env bash\ntar -czf /root/backup-$(date +%F).tgz /etc' | sudo tee /usr/local/sbin/backup.sh
sudo chmod +x /usr/local/sbin/backup.sh

sudo tee /etc/systemd/system/backup.service >/dev/null <<'UNIT'
[Unit]
Description=Backup etc
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/backup.sh
UNIT

sudo tee /etc/systemd/system/backup.timer >/dev/null <<'UNIT'
[Unit]
Description=Backup diario 02:00
[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
[Install]
WantedBy=timers.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now backup.timer
```

### 25) Alternativa com cron diário 02:00

```bash
echo '0 2 * * * /usr/local/sbin/backup.sh' | sudo crontab -
```

---

## 🔹 Autofs & NFS

### 26) Configurar autofs para montar /projetos de nfs01:/exports/projetos

```bash
echo '/projetos  /etc/auto.projetos' | sudo tee /etc/auto.master.d/projetos.autofs
echo 'repos nfs01:/exports/projetos' | sudo tee /etc/auto.projetos
sudo systemctl enable --now autofs
ls /projetos/repos
```

### 27) Montagem NFS persistente via fstab

```bash
sudo mkdir -p /mnt/backup
echo 'nfs01:/exports/backup /mnt/backup nfs4 defaults 0 0' | sudo tee -a /etc/fstab
sudo mount -a && findmnt /mnt/backup
```

---

## 🔹 Podman (containers)

### 28) Subir container web publicado em 8080 com restart always

```bash
sudo systemctl enable --now podman
podman run -d --name web -p 8080:80 --restart=always docker.io/library/nginx:alpine
```

### 29) Persistir container via systemd unit gerada

```bash
podman generate systemd --name web | sudo tee /etc/systemd/system/container-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now container-web.service
```

---

## 🔹 Pacotes & Repositórios

### 30) Instalar pacotes essenciais e verificar origem

```bash
sudo dnf install -y lvm2 xfsprogs policycoreutils-python-utils autofs firewalld chrony
rpm -qi lvm2 | grep -E 'Name|Version|From repo'
```

