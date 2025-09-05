<img width="1536" height="1024" alt="ChatGPT Image 5 de set  de 2025, 00_21_48" src="https://github.com/user-attachments/assets/279a94a5-5902-40d2-b9c1-2cc571013715" />

[![Shell](https://img.shields.io/badge/shell-bash-1f425f.svg)](https://www.gnu.org/software/bash/)
[![RHEL](https://img.shields.io/badge/RHEL-9.3-red.svg)](https://www.redhat.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Status](https://img.shields.io/badge/status-active-success.svg)](#)

> “Um coach de terminal que te acompanha em background e valida, em tempo real, as tarefas do RHCSA EX200.”

O **RHCSA Coach** instala um serviço **systemd (modo usuário)** e um **hook de Bash** que monitora os comandos executados, reconhece ações relevantes (LVM, SELinux, firewalld, nmcli, podman, quotas, etc.) e dispara **checagens de estado**. A cada progresso, você recebe feedback **imediato** no prompt (✅/❌ + dica prática).  
Perfeito para estudo individual e demonstrações em aula.

---

## 📑 Sumário

- [Destaques](#-destaques)
- [Requisitos](#-requisitos)
- [Instalação Rápida](#-instalação-rápida)
- [Como Funciona](#-como-funciona)
- [Comandos Principais](#-comandos-principais)
- [Logs & Feedbacks](#-logs--feedbacks)
- [Solução de Problemas](#-solução-de-problemas)
- [Compatibilidade](#-compatibilidade)
- [License](#license)

---

## ✨ Destaques

- 🧠 **Coach em background:** roda como `systemd --user` (sem precisar root).
- ⌨️ **Hook no Bash:** captura comandos via `PROMPT_COMMAND`.
- 🔎 **Validação real:** confere estado do sistema (LVM, SELinux, fstab, firewalld, nmcli…).
- ⚡ **Feedback imediato:** mostra no próximo prompt e registra em log.
- 🧩 **Extensível:** adicione seus próprios `check_*` e *triggers* por regex.
- 🔁 **Reset/Deep Reset:** recomece o laboratório quando quiser.
- 📘 [Acesse aqui o Questionário completo de preparação RHCSA EX200](https://github.com/viniciushammett/RHCSA-Coach/blob/main/Questionario.md)

---

## 📦 Requisitos

Pacotes recomendados:

```bash
sudo dnf install -y policycoreutils-python-utils lvm2 xfsprogs autofs firewalld chrony podman tar rsyslog
```
> Testado em RHEL 9.3 (compatível com Rocky/Alma 9.x).

##
### 🚀 Instalação Rápida

Salve o script neste repo como rhcsa_coach.sh e torne-o executável:
```bash
chmod +x rhcsa-coach.sh
```
Instale:
```bash
./rhcsa-coach.sh --install
```
>**Abra um novo terminal (ou source ~/.bashrc) para ativar o hook.**

>**Use normalmente. O coach validará a cada comando relevante.**

##
### ⚙️ Como Funciona
- O hook adiciona, a cada comando, uma linha em `~/.rhcsa-coach/cmd.log.`
- O daemon (serviço user systemd) acompanha este arquivo com `tail -F.`
- Quando detecta um comando que bate com algum padrão (regex), chama as funções `check_*` correspondentes.
- O resultado aparece:
  - no terminal (no próximo prompt),
  - em ~/.rhcsa-coach/feedback.log,
  - e o progresso fica marcado em ~/.rhcsa-coach/state.json.

##
### 🧰 Comandos Principais
Pelo script
```bash
./rhcsa-coach.sh --install       # instala, cria serviço e ativa
./rhcsa-coach.sh --uninstall     # remove serviço, binário e diretório
./rhcsa-coach.sh --reset         # zera progresso (state) e feedbacks
./rhcsa-coach.sh --deep-reset    # idem + zera cmd.log (histórico)
```
Pelo binário (instalado em ~/.local/bin)
```bash
rhcsa-coach status      # checklist de progresso
rhcsa-coach log         # últimas mensagens
rhcsa-coach reset       # reset normal
rhcsa-coach deep-reset  # deep reset
```
##
### 🧾 Logs & Feedbacks
- Ver últimos feedbacks: `rhcsa-coach log`
- Arquivos:
  - `~/.rhcsa-coach/feedback.log` – histórico de ✅/❌
  - `~/.rhcsa-coach/last.msg` – mensagem exibida no próximo prompt
  - `~/.rhcsa-coach/state.json` – progresso em formato chave: true/false
##
### 🧩 Solução de Problemas

- Feedback não aparece no prompt
  → Abra um novo terminal ou rode `source ~/.bashrc.`

- Serviço não inicia
  → Verifique `systemctl --user status rhcsa-coach.service` e `journalctl --user -u rhcsa-coach -e`.

- Regras permanentes do firewall não listam
  → Use root para `firewall-cmd --permanent ...` (o coach detecta, mas pode não conseguir listar sem permissão).

- nmcli não encontra a conexão
  → Crie/modifique a conexão com o nome configurado em `NMCLI_CONN_NAME`.

- Paths/nomes diferentes do seu lab
  → Ajuste o bloco **CONFIG** no script e reinstale.
##
### 🖥️ Compatibilidade
- SO: RHEL 9.3
- Shell: Bash (o hook usa `PROMPT_COMMAND`)
- Init: systemd (modo usuário)
##
### License
> Este projeto está licenciado sob a MIT License — veja o arquivo LICENSE para mais detalhes.
