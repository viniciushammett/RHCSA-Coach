#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# RHCSA Coach – Background validator/coach para EX200 (RHEL 9.3)
# =============================================================================
# Modo de uso:
#   ./rhcsa_coach.sh --install      # instala, cria serviço user systemd e ativa
#   ./rhcsa_coach.sh --uninstall    # remove tudo
#   ./rhcsa_coach.sh --reset        # zera progresso e feedbacks
#   ./rhcsa_coach.sh --deep-reset   # idem + zera cmd.log (histórico)
#   rhcsa-coach {status|log|reset|deep-reset}
#
# Funcionamento:
# - Hook em Bash (PROMPT_COMMAND) registra cada comando em ~/.rhcsa-coach/cmd.log
# - Daemon (systemd --user) vigia cmd.log; quando encontra comandos relevantes,
#   roda checagens de estado e grava feedback em ~/.rhcsa-coach/last.msg
# - No próximo prompt, o hook exibe o feedback no seu terminal.
#
# Requisitos recomendados:
#   dnf install -y policycoreutils-python-utils lvm2 xfsprogs autofs firewalld \
#                  chrony podman tar rsyslog
# =============================================================================

APP_NAME="rhcsa-coach"
APP_DIR="${HOME}/.rhcsa-coach"
BIN_DIR="${HOME}/.local/bin"
UNIT_DIR="${HOME}/.config/systemd/user"
UNIT_FILE="${UNIT_DIR}/${APP_NAME}.service"
BIN_FILE="${BIN_DIR}/${APP_NAME}"
CMD_LOG="${APP_DIR}/cmd.log"
STATE_DB="${APP_DIR}/state.json"
FEEDBACK_LAST="${APP_DIR}/last.msg"
FEEDBACK_LOG="${APP_DIR}/feedback.log"

# ------------------------------- CONFIG --------------------------------------
EXPECTED_HOSTNAME="lab.example.com"

PROJECT_DIR="/srv/projetos"
PROJECT_COLAB_DIR="${PROJECT_DIR}/colab"
PROJECT_GROUP="devs"

LVM_PV="/dev/vdc"
LVM_VG="vgapp"
LVM_LV="lvlogs"
LVM_SIZE_MIN_G=5
LVM_MOUNTPOINT="/ponto_de_montagem"
LVM_FS_TYPE="xfs"

QUOTA_MOUNT="/home"

FW_EXTRA_PORT="8080/tcp"

SSHD_CONFIG="/etc/ssh/sshd_config"
EXPECT_PERMIT_ROOT_LOGIN="no"
EXPECT_PASSWORD_AUTH="no"

NMCLI_CONN_NAME="lab-static"

PODMAN_CONTAINER="web"
PODMAN_PUBLISHED_PORT="8080"

BACKUP_SCRIPT="/usr/local/sbin/backup.sh"
BACKUP_SERVICE="backup.service"
BACKUP_TIMER="backup.timer"

SELINUX_HTTPD_PATH="/srv/www"
SELINUX_HTTPD_TYPE="httpd_sys_content_t"
SELINUX_BOOL_NET="httpd_can_network_connect"

SYSCTL_FILE="/etc/sysctl.d/99-sysctl.conf"
SYSCTL_KEY="net.ipv4.ip_forward"
SYSCTL_EXPECTED="1"

JOURNALD_CONF="/etc/systemd/journald.conf"
# -----------------------------------------------------------------------------

# ------------------------------ Utilidades -----------------------------------
now() { date +"%F %T"; }

ensure_dirs() {
  mkdir -p "$APP_DIR" "$BIN_DIR" "$UNIT_DIR"
  [[ -e "$CMD_LOG" ]] || : > "$CMD_LOG"
  [[ -s "$STATE_DB" ]] || echo "{}" > "$STATE_DB"
  [[ -e "$FEEDBACK_LOG" ]] || : > "$FEEDBACK_LOG"
  : > "$FEEDBACK_LAST"
}

say() { printf "[%s] %s\n" "$APP_NAME" "$*"; }
green() { printf "\033[1;32m%s\033[0m\n" "$*"; }
red()   { printf "\033[1;31m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[1;33m%s\033[0m\n" "$*"; }

feedback() {
  local msg="$*"
  printf "%s\n" "$msg" > "$FEEDBACK_LAST"
  printf "[%s] %s\n" "$(now)" "$msg" >> "$FEEDBACK_LOG"
}

json_get() { awk -v k="\"$1\"" -F: '$1 ~ k {gsub(/[ ,\r\n]/,"",$2); if ($2 ~ /true/) { print "true"; exit } else { print "false"; exit }}' || true; }

json_set_true() {
  local key="$1"
  if [[ ! -s "$STATE_DB" ]]; then
    printf '{ "%s": true }\n' "$key" > "$STATE_DB"; return
  fi
  if grep -q "\"$key\"" "$STATE_DB"; then
    sed -i "s/\"$key\"[[:space:]]*:[[:space:]]*false/\"$key\": true/g" "$STATE_DB"
  else
    sed -i "s/}/, \"$key\": true }/" "$STATE_DB"
  fi
}

bool_mark_ok() { json_set_true "$1"; feedback "✅ $2"; }
bool_mark_nok(){ feedback "❌ $1"; }
have_cmd() { command -v "$1" &>/dev/null; }

# ------------------------------ Checagens ------------------------------------
check_selinux_enforcing() {
  local ok=1
  if have_cmd getenforce && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then :; else ok=0; yellow "SELinux não está Enforcing. → setenforce 1 e ajuste /etc/selinux/config"; fi
  if [[ $ok -eq 1 ]]; then bool_mark_ok "selinux_enforcing" "SELinux em modo Enforcing."; else bool_mark_nok "SELinux: ajuste necessário (ver dica acima)."; fi
}

check_selinux_httpd() {
  local ok=1
  if have_cmd semanage && semanage fcontext -l 2>/dev/null | grep -qE "^${SELINUX_HTTPD_PATH//\//\\/}\\(/\\.\\*\\)\\?\\s+\\(all files\\).*${SELINUX_HTTPD_TYPE}"; then :; else
    ok=0; yellow "Fcontext ausente: semanage fcontext -a -t ${SELINUX_HTTPD_TYPE} \"${SELINUX_HTTPD_PATH}(/.*)?\"; restorecon -RFv ${SELINUX_HTTPD_PATH}"
  fi
  if have_cmd getsebool && getsebool "$SELINUX_BOOL_NET" 2>/dev/null | grep -q 'on$'; then :; else
    ok=0; yellow "Boolean ${SELINUX_BOOL_NET} OFF → setsebool -P ${SELINUX_BOOL_NET} on"
  fi
  if [[ $ok -eq 1 ]]; then bool_mark_ok "selinux_httpd" "SELinux/httpd: fcontext + boolean ok."; else bool_mark_nok "SELinux/httpd: pendências."; fi
}

check_lvm_logs() {
  local ok=1
  vgs "$LVM_VG" &>/dev/null || { ok=0; yellow "VG '$LVM_VG' ausente. → pvcreate ${LVM_PV}; vgcreate ${LVM_VG} ${LVM_PV}"; }
  if lvs "${LVM_VG}/${LVM_LV}" &>/dev/null; then
    local sz; sz=$(lvs --noheadings -o LV_SIZE --units g --nosuffix "${LVM_VG}/${LVM_LV}" | awk '{print int($1)}' || echo 0)
    [[ -n "$sz" && "$sz" -ge "$LVM_SIZE_MIN_G" ]] || { ok=0; yellow "LV '${LVM_LV}' < ${LVM_SIZE_MIN_G}G → lvextend -L ${LVM_SIZE_MIN_G}G ${LVM_VG}/${LVM_LV}"; }
  else
    ok=0; yellow "LV '${LVM_LV}' ausente. → lvcreate -L ${LVM_SIZE_MIN_G}G -n ${LVM_LV} ${LVM_VG}"
  fi
  blkid -o value -s TYPE "/dev/${LVM_VG}/${LVM_LV}" 2>/dev/null | grep -q "$LVM_FS_TYPE" || { ok=0; yellow "FS != ${LVM_FS_TYPE}. → mkfs.${LVM_FS_TYPE} /dev/${LVM_VG}/${LVM_LV}"; }
  findmnt -no TARGET "/dev/${LVM_VG}/${LVM_LV}" 2>/dev/null | grep -qx "$LVM_MOUNTPOINT" || { ok=0; yellow "Não montado em ${LVM_MOUNTPOINT}. → mkdir -p ${LVM_MOUNTPOINT}; echo '/dev/${LVM_VG}/${LVM_LV} ${LVM_MOUNTPOINT} ${LVM_FS_TYPE} defaults 0 0' >> /etc/fstab; mount -a"; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "lvm_logs" "LVM ${LVM_VG}/${LVM_LV} em ${LVM_MOUNTPOINT} ok."; else bool_mark_nok "LVM/FS: pendências."; fi
}

check_lvm_snapshot() {
  if lvs "${LVM_VG}/${LVM_LV}_snap" &>/dev/null; then
    bool_mark_ok "lvm_snap" "Snapshot ${LVM_LV}_snap existe."
  else
    bool_mark_nok "Snapshot LVM ausente. → lvcreate -s -n ${LVM_LV}_snap -L 1G ${LVM_VG}/${LVM_LV}"
  fi
}

check_autofs() {
  local ok=1
  ls /etc/auto.master.d/*.autofs &>/dev/null || { ok=0; yellow "Mapa autofs ausente em /etc/auto.master.d/*.autofs"; }
  systemctl is-enabled autofs &>/dev/null || { ok=0; yellow "autofs não habilitado. → systemctl enable --now autofs"; }
  systemctl is-active autofs &>/dev/null || { ok=0; yellow "autofs não ativo. → systemctl start autofs"; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "autofs" "Autofs ativo e mapeado."; else bool_mark_nok "Autofs: pendências."; fi
}

check_users_groups() {
  local ok=1
  getent group "$PROJECT_GROUP" &>/dev/null || { ok=0; yellow "Grupo '$PROJECT_GROUP' ausente. → groupadd ${PROJECT_GROUP}"; }
  id ana &>/dev/null || { ok=0; yellow "Usuária 'ana' ausente. → useradd -m -s /bin/bash -G ${PROJECT_GROUP} ana"; }
  if id ana &>/dev/null; then
    id -nG ana | tr ' ' '\n' | grep -qx "$PROJECT_GROUP" || { ok=0; yellow "'ana' fora do grupo ${PROJECT_GROUP}. → usermod -aG ${PROJECT_GROUP} ana"; }
    local home; home=$(getent passwd ana | cut -d: -f6)
    if [[ -n "$home" && -d "$home" ]]; then
      local perm; perm=$(stat -c %a "$home")
      [[ "$perm" =~ ^(700|750)$ ]] || { ok=0; yellow "Permissão home 'ana' ($perm) incorreta. → chmod 700 \"$home\""; }
    fi
  fi
  if [[ $ok -eq 1 ]]; then bool_mark_ok "users_groups" "Usuária 'ana' e grupo '${PROJECT_GROUP}' ok."; else bool_mark_nok "Usuários/Grupos: pendências."; fi
}

check_acl_sgid() {
  local ok=1
  mkdir -p "$PROJECT_COLAB_DIR" || true
  chgrp "$PROJECT_GROUP" "$PROJECT_COLAB_DIR" 2>/dev/null || true
  [[ "$(stat -c %A "$PROJECT_COLAB_DIR" 2>/dev/null)" =~ s ]] || { ok=0; yellow "SGID ausente em ${PROJECT_COLAB_DIR}. → chmod 2775 ${PROJECT_COLAB_DIR}"; }
  if have_cmd getfacl && getfacl -p "$PROJECT_COLAB_DIR" 2>/dev/null | grep -q "default:group:${PROJECT_GROUP}:rwx"; then :; else
    ok=0; yellow "ACL default ausente. → setfacl -m d:g:${PROJECT_GROUP}:rwx ${PROJECT_COLAB_DIR}"
  fi
  if [[ $ok -eq 1 ]]; then bool_mark_ok "acl_sgid" "SGID + ACL default em ${PROJECT_COLAB_DIR} ok."; else bool_mark_nok "ACL/SGID: pendências."; fi
}

check_xfs_quotas() {
  local ok=1
  grep -Eqs "[[:space:]]${QUOTA_MOUNT}[[:space:]].*xfs.*(uquota|gquota|prjquota)" /etc/fstab || { ok=0; yellow "fstab sem quotas em ${QUOTA_MOUNT}. → adicionar uquota/gquota e remount"; }
  if have_cmd xfs_quota && mount | awk '{print $3,$5}' | grep -qE "^${QUOTA_MOUNT}[[:space:]]xfs$"; then
    xfs_quota -x -c "state" "$QUOTA_MOUNT" 2>/dev/null | grep -q "User quota state.*ON" || { ok=0; yellow "User quota OFF em ${QUOTA_MOUNT}. → garantir 'uquota' e remontar"; }
  fi
  if [[ $ok -eq 1 ]]; then bool_mark_ok "xfs_quotas" "Quotas XFS ativas em ${QUOTA_MOUNT}."; else bool_mark_nok "XFS quotas: pendências."; fi
}

check_firewalld() {
  local ok=1
  systemctl is-active firewalld &>/dev/null || { ok=0; yellow "firewalld inativo. → systemctl enable --now firewalld"; }
  firewall-cmd --permanent --list-services &>/dev/null || { ok=0; yellow "firewall-cmd sem permissão. Rode como root para validar regras permanentes."; }
  firewall-cmd --permanent --list-services 2>/dev/null | tr ' ' '\n' | grep -qx http || { ok=0; yellow "Serviço 'http' ausente. → firewall-cmd --permanent --add-service=http && firewall-cmd --reload"; }
  firewall-cmd --permanent --list-ports 2>/dev/null | tr ' ' '\n' | grep -qx "$FW_EXTRA_PORT" || { ok=0; yellow "Porta ${FW_EXTRA_PORT} ausente. → firewall-cmd --permanent --add-port=${FW_EXTRA_PORT} && firewall-cmd --reload"; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "firewalld" "firewalld/HTTP/porta ok."; else bool_mark_nok "firewalld: pendências."; fi
}

check_nmcli_static() {
  have_cmd nmcli || { bool_mark_nok "nmcli não instalado."; return; }
  local method dns
  method=$(nmcli -g ipv4.method connection show "$NMCLI_CONN_NAME" 2>/dev/null || echo "")
  dns=$(nmcli -g ipv4.dns connection show "$NMCLI_CONN_NAME" 2>/dev/null || echo "")
  if [[ "$method" == "manual" && -n "$dns" ]]; then
    bool_mark_ok "nmcli_static" "Conexão '${NMCLI_CONN_NAME}' com IPv4 manual + DNS."
  else
    bool_mark_nok "NMCLI: defina método 'manual' e DNS na conexão '${NMCLI_CONN_NAME}'."
  fi
}

check_hostname() {
  local h; h=$(hostname -f 2>/dev/null || hostname)
  if [[ "$h" == "$EXPECTED_HOSTNAME" ]]; then
    bool_mark_ok "hostname" "Hostname FQDN '${EXPECTED_HOSTNAME}'."
  else
    bool_mark_nok "Hostname atual '${h}'. → hostnamectl set-hostname ${EXPECTED_HOSTNAME}"
  fi
}

check_sshd() {
  local ok=1
  [[ -r "$SSHD_CONFIG" ]] || { bool_mark_nok "sshd_config não legível. Execute como root."; return; }
  grep -Eq "^[#[:space:]]*PermitRootLogin[[:space:]]+$EXPECT_PERMIT_ROOT_LOGIN\b" "$SSHD_CONFIG" || { ok=0; yellow "SSHD: defina PermitRootLogin ${EXPECT_PERMIT_ROOT_LOGIN} em $SSHD_CONFIG"; }
  grep -Eq "^[#[:space:]]*PasswordAuthentication[[:space:]]+$EXPECT_PASSWORD_AUTH\b" "$SSHD_CONFIG" || { ok=0; yellow "SSHD: ajuste PasswordAuthentication ${EXPECT_PASSWORD_AUTH} (se exigido)"; }
  systemctl is-active sshd &>/dev/null || { ok=0; yellow "sshd inativo. → systemctl enable --now sshd"; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "sshd" "SSHD endurecido e ativo."; else bool_mark_nok "SSHD: pendências."; fi
}

check_chrony() {
  local ok=1
  systemctl is-active chronyd &>/dev/null || { ok=0; yellow "chronyd inativo. → systemctl enable --now chronyd"; }
  if have_cmd chronyc && chronyc tracking &>/dev/null; then
    chronyc sources -v 2>/dev/null | grep -Eq '^\^\*|\^\+' || { ok=0; yellow "chrony sem fonte válida. → verifique /etc/chrony.conf"; }
  fi
  if [[ $ok -eq 1 ]]; then bool_mark_ok "chrony" "Chrony ativo com fonte válida."; else bool_mark_nok "Chrony: pendências."; fi
}

check_journald_persistent() {
  local ok=1
  grep -Eq "^[#[:space:]]*Storage[[:space:]]*=[[:space:]]*persistent\b" "$JOURNALD_CONF" 2>/dev/null || { [[ -d /var/log/journal ]] || ok=0; }
  systemctl is-active systemd-journald &>/dev/null || { ok=0; yellow "systemd-journald inativo?"; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "journald_persistent" "journald com armazenamento persistente."; else bool_mark_nok "journald: habilite Storage=persistent em $JOURNALD_CONF e systemctl restart systemd-journald"; fi
}

check_sysctl_ipforward() {
  local ok=1
  [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" == "$SYSCTL_EXPECTED" ]] || { ok=0; yellow "Runtime net.ipv4.ip_forward != ${SYSCTL_EXPECTED} → sysctl -w ${SYSCTL_KEY}=${SYSCTL_EXPECTED}"; }
  grep -Eq "^[#[:space:]]*${SYSCTL_KEY}[[:space:]]*=[[:space:]]*${SYSCTL_EXPECTED}\b" "$SYSCTL_FILE" 2>/dev/null || { ok=0; yellow "Persistência ausente em ${SYSCTL_FILE}. Adicione: ${SYSCTL_KEY}=${SYSCTL_EXPECTED}"; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "sysctl_ipforward" "IP forwarding ativo e persistente."; else bool_mark_nok "sysctl/ip_forward: pendências."; fi
}

check_backup_timer() {
  local ok=1
  [[ -x "$BACKUP_SCRIPT" ]] || { ok=0; yellow "Script backup ausente/não-executável: ${BACKUP_SCRIPT}"; }
  systemctl is-enabled "$BACKUP_SERVICE" &>/dev/null || { ok=0; yellow "${BACKUP_SERVICE} não habilitado."; }
  systemctl is-enabled "$BACKUP_TIMER" &>/dev/null || { ok=0; yellow "${BACKUP_TIMER} não habilitado."; }
  systemctl is-active "$BACKUP_TIMER" &>/dev/null || { ok=0; yellow "${BACKUP_TIMER} não ativo."; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "backup_timer" "Backup service/timer prontos."; else bool_mark_nok "Backup service/timer: pendências."; fi
}

check_cron_backup() {
  local ok=1
  crontab -l 2>/dev/null | grep -q "$BACKUP_SCRIPT" || { ok=0; yellow "Crontab não referencia ${BACKUP_SCRIPT}. → crontab -e"; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "cron_backup" "Cron chamando backup.sh ok."; else bool_mark_nok "Cron backup: pendências."; fi
}

check_podman_web() {
  have_cmd podman || { bool_mark_nok "podman não instalado."; return; }
  local ok=1
  podman ps --format '{{.Names}} {{.Ports}} {{.Status}}' | grep -E "^${PODMAN_CONTAINER}[[:space:]]" >/dev/null || { ok=0; yellow "Container '${PODMAN_CONTAINER}' não está rodando. Ex.: podman run -d --name ${PODMAN_CONTAINER} -p ${PODMAN_PUBLISHED_PORT}:80 --restart=always docker.io/library/nginx:alpine"; }
  podman ps --format '{{.Names}} {{.Ports}}' | grep -E "^${PODMAN_CONTAINER}[[:space:]].*${PODMAN_PUBLISHED_PORT}/tcp" >/dev/null || { ok=0; yellow "Publish ${PODMAN_PUBLISHED_PORT}->80 ausente no container ${PODMAN_CONTAINER}."; }
  podman inspect "${PODMAN_CONTAINER}" 2>/dev/null | grep -q '"RestartPolicy": *"always"' || { ok=0; yellow "RestartPolicy != always. → use --restart=always ou systemd (podman generate systemd)"; }
  if [[ $ok -eq 1 ]]; then bool_mark_ok "podman_web" "Podman '${PODMAN_CONTAINER}' em ${PODMAN_PUBLISHED_PORT} (restart=always)."; else bool_mark_nok "Podman: pendências."; fi
}

check_nfs_fstab_mount() {
  local ok=1
  if grep -Eq ' nfs(4)? ' /etc/fstab; then
    mount | grep -q ' type nfs' || { ok=0; yellow "NFS em fstab mas não montado. → mount -a (verifique servidor)"; }
    if [[ $ok -eq 1 ]]; then bool_mark_ok "nfs_mount" "NFS presente em fstab e montado."; else bool_mark_nok "NFS: verifique servidor e fstab."; fi
  else
    bool_mark_nok "Sem entradas NFS no fstab (ignore se não exigido)."
  fi
}

check_umask_027() {
  if grep -Eq '(^|[[:space:]])umask[[:space:]]+027\b' /etc/profile /etc/bashrc 2>/dev/null; then
    bool_mark_ok "umask_027" "Umask 027 definido (global)."
  else
    bool_mark_nok "Umask 027 ausente. → adicionar 'umask 027' em /etc/profile.d/seguranca.sh"
  fi
}

# --------------------- Mapeamento de Gatilhos (regex->função) -----------------
declare -A TRIGGERS=(
  ["semanage fcontext|restorecon|setsebool|getsebool|sestatus|getenforce"]="check_selinux_httpd check_selinux_enforcing"
  ["pvcreate|vgcreate|lvcreate|lvextend|lvreduce|mkfs\\.|xfs_growfs|mount|findmnt|blkid|lsblk"]="check_lvm_logs check_lvm_snapshot"
  ["autofs|auto\\.master|systemctl .* autofs"]="check_autofs"
  ["useradd|usermod|groupadd|getfacl|setfacl|chmod .* 2[0-7][0-7][0-7]|chmod .* g\\+s"]="check_users_groups check_acl_sgid"
  ["xfs_quota|fstab|mount -o remount|mount -a"]="check_xfs_quotas"
  ["firewall-cmd|systemctl .* firewalld"]="check_firewalld"
  ["nmcli|connection add|connection modify|device set"]="check_nmcli_static"
  ["hostnamectl|hostname"]="check_hostname"
  ["sshd|systemctl .* sshd|vi .*sshd_config|sed .*sshd_config"]="check_sshd"
  ["chronyc|systemctl .* chronyd|vi .*chrony.conf"]="check_chrony"
  ["systemctl .* systemd-journald|vi .*journald.conf|sed .*journald.conf"]="check_journald_persistent"
  ["sysctl|vi .*sysctl\\.conf|sysctl\\.d"]="check_sysctl_ipforward"
  ["systemctl .* ${BACKUP_TIMER}|systemctl .* ${BACKUP_SERVICE}|crontab"]="check_backup_timer check_cron_backup"
  ["podman run|podman create|podman start|podman generate systemd|podman inspect|podman ps"]="check_podman_web"
  ["/etc/fstab|mount .* nfs|showmount|exportfs"]="check_nfs_fstab_mount"
  ["umask|/etc/profile|/etc/bashrc|/etc/profile\\.d"]="check_umask_027"
)

run_checks_for_command() {
  local cmd="$1"
  cmd="$(echo "$cmd" | sed 's/[[:space:]]\+/ /g')"
  for pattern in "${!TRIGGERS[@]}"; do
    if echo "$cmd" | grep -Eiq -- "$pattern"; then
      for fn in ${TRIGGERS[$pattern]}; do
        type "$fn" &~/dev/null || true
        "$fn"
      done
    fi
  done
}

# ------------------------------ Daemon Loop -----------------------------------
daemon_loop() {
  say "Daemon iniciado. Acompanhando $CMD_LOG"
  tail -Fn0 "$CMD_LOG" | while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    run_checks_for_command "$line"
  done
}

# --------------------------- Reset do estado/logs -----------------------------
do_reset_files() {
  echo "{}" > "$STATE_DB"
  : > "$FEEDBACK_LAST"
  : > "$FEEDBACK_LOG"
  say "Reset concluído: $STATE_DB, $FEEDBACK_LAST, $FEEDBACK_LOG"
}

do_deep_reset_files() {
  do_reset_files
  : > "$CMD_LOG"
  say "Deep reset: também limpei $CMD_LOG"
}

# ------------------------------- CLI (status) ---------------------------------
install_cli_bin() {
  cat >"$BIN_FILE" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${HOME}/.rhcsa-coach"
STATE_DB="${APP_DIR}/state.json"
FEEDBACK_LOG="${APP_DIR}/feedback.log"
CMD_LOG="${APP_DIR}/cmd.log"
FEEDBACK_LAST="${APP_DIR}/last.msg"

show_status() {
  [[ -s "$STATE_DB" ]] || echo "{}" > "$STATE_DB"
  declare -A TASKS=(
    ["selinux_enforcing"]="SELinux Enforcing"
    ["selinux_httpd"]="SELinux httpd (/srv/www + boolean)"
    ["lvm_logs"]="LVM vg/lv montado"
    ["lvm_snap"]="Snapshot LVM"
    ["autofs"]="Autofs ativo e mapeado"
    ["users_groups"]="Usuária 'ana' + grupo 'devs'"
    ["acl_sgid"]="ACL default + SGID em dir colab"
    ["xfs_quotas"]="Quotas XFS ativas"
    ["firewalld"]="firewalld + http + 8080/tcp"
    ["nmcli_static"]="Conexão nmcli 'lab-static' manual + DNS"
    ["hostname"]="Hostname FQDN esperado"
    ["sshd"]="SSHD endurecido e ativo"
    ["chrony"]="Chrony ativo com fonte"
    ["journald_persistent"]="journald persistente"
    ["sysctl_ipforward"]="IP forwarding runtime+persist"
    ["backup_timer"]="Systemd backup service+timer"
    ["cron_backup"]="Cron chamando backup.sh"
    ["podman_web"]="Podman web 8080 com restart"
    ["nfs_mount"]="NFS em fstab e montado"
    ["umask_027"]="Umask 027 global"
  )
  local completed=0 total=0
  echo "== Progresso RHCSA Coach =="
  for key in "${!TASKS[@]}"; do
    total=$((total+1))
    if awk -v k="\"$key\"" -F: '$1 ~ k && $2 ~ /true/ {found=1} END{exit found?0:1}' "$STATE_DB"; then
      printf "  %s %s\n" "✅" "${TASKS[$key]}"
      completed=$((completed+1))
    else
      printf "  %s %s\n" "❌" "${TASKS[$key]}"
    fi
  done
  echo; printf "Concluídas: %d/%d\n" "$completed" "$total"
}

show_log() {
  [[ -f "$FEEDBACK_LOG" ]] || { echo "Sem logs ainda."; exit 0; }
  tail -n 100 "$FEEDBACK_LOG"
}

reset_state() {
  echo "{}" > "$STATE_DB"
  : > "$FEEDBACK_LAST"
  : > "$FEEDBACK_LOG"
  echo "Reset concluído: $STATE_DB, $FEEDBACK_LAST, $FEEDBACK_LOG"
}

deep_reset_state() {
  reset_state
  : > "$CMD_LOG"
  echo "Deep reset: também limpei $CMD_LOG"
}

case "${1:-status}" in
  status)      show_status ;;
  log)         show_log ;;
  reset)       reset_state ;;
  deep-reset)  deep_reset_state ;;
  *)
    echo "Uso: rhcsa-coach {status|log|reset|deep-reset}"
    exit 1
    ;;
esac
EOF
  chmod +x "$BIN_FILE"
}

# --------------------------- systemd (user) unit ------------------------------
install_unit() {
  cat >"$UNIT_FILE" <<EOF
[Unit]
Description=RHCSA Coach (background validator)
After=default.target

[Service]
Type=simple
ExecStart=${APP_DIR}/daemon.sh
Restart=always
RestartSec=1

[Install]
WantedBy=default.target
EOF
}

install_daemon_script() {
  cat >"${APP_DIR}/daemon.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${HOME}/.rhcsa-coach"
CMD_LOG="${APP_DIR}/cmd.log"
MAIN="${APP_DIR}/main.sh"
source "$MAIN"
daemon_loop
EOF
  chmod +x "${APP_DIR}/daemon.sh"
}

install_main_lib() {
  cp "$0" "${APP_DIR}/main.sh"
}

# ----------------------------- Hook do Bash -----------------------------------
install_shell_hook() {
  local hook='
# >>> rhcsa-coach hook >>>
if [ -n "$BASH_VERSION" ]; then
  RHCSA_COACH_DIR="${HOME}/.rhcsa-coach"
  RHCSA_COACH_LOG="${RHCSA_COACH_DIR}/cmd.log"
  RHCSA_COACH_LAST="${RHCSA_COACH_DIR}/last.msg"
  _rhcsa_coach_log_cmd() {
    local last
    last=$(HISTTIMEFORMAT= history 1 | sed "s/^[ ]*[0-9]\+[ ]*//")
    [ -n "$last" ] && printf "%s\n" "$last" >> "$RHCSA_COACH_LOG"
  }
  _rhcsa_coach_show_feedback() {
    if [ -s "$RHCSA_COACH_LAST" ]; then
      echo
      cat "$RHCSA_COACH_LAST"
      : > "$RHCSA_COACH_LAST"
    fi
  }
  shopt -s histappend
  PROMPT_COMMAND="_rhcsa_coach_log_cmd; _rhcsa_coach_show_feedback; history -a; history -n; $PROMPT_COMMAND"
fi
# <<< rhcsa-coach hook <<<
'
  local bashrc="${HOME}/.bashrc"
  if ! grep -q "rhcsa-coach hook" "$bashrc" 2>/dev/null; then
    printf "\n%s\n" "$hook" >> "$bashrc"
    say "Hook adicionado em $bashrc (abra um novo shell para ativar)."
  else
    say "Hook já presente em $bashrc"
  fi
}

# --------------------------- Instalar/Desinstalar -----------------------------
do_install() {
  ensure_dirs
  install_cli_bin
  install_unit
  install_main_lib
  install_daemon_script
  install_shell_hook
  systemctl --user daemon-reload
  systemctl --user enable --now "${APP_NAME}.service"
  echo
  green "✅ Instalado!"
  echo "• Serviço (user): ${APP_NAME}.service (ativo)"
  echo "• CLI: ${BIN_FILE}  →  use: ${APP_NAME} status | ${APP_NAME} log | ${APP_NAME} reset"
  echo "• Logs: ${FEEDBACK_LOG}"
  yellow "Abra um NOVO terminal para ativar o hook (PROMPT_COMMAND) ou execute: source ~/.bashrc"
}

do_uninstall() {
  set +e
  systemctl --user disable --now "${APP_NAME}.service" 2>/dev/null
  rm -f "$UNIT_FILE"
  systemctl --user daemon-reload
  rm -f "$BIN_FILE"
  rm -rf "$APP_DIR"
  sed -i '/rhcsa-coach hook/,+30d' "${HOME}/.bashrc" 2>/dev/null || true
  green "Removido."
}

# ------------------------------- Main Guard -----------------------------------
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    --install)     do_install ;;
    --uninstall)   do_uninstall ;;
    --reset)       do_reset_files ;;
    --deep-reset)  do_deep_reset_files ;;
    *)
      echo "Uso:"
      echo "  $0 --install       # instala e inicia serviço user systemd"
      echo "  $0 --uninstall     # remove tudo"
      echo "  $0 --reset         # zera progresso e feedbacks (state.json/feedbacks)"
      echo "  $0 --deep-reset    # idem + zera cmd.log (não reprocessa histórico)"
      echo
      echo "Após instalar: abra novo terminal e use: ${APP_NAME} status | ${APP_NAME} log | ${APP_NAME} reset"
      ;;
  esac
fi
