# Recon Tool

Un outil de reconnaissance automatisé pour CTF qui enchaîne les phases nmap et gobuster sans bloquer votre console.

## Installation

### Installation rapide depuis les releases

```bash
# Linux AMD64
wget https://github.com/VOTRE_USERNAME/recon-tools/releases/latest/download/recon-tool-linux-amd64
chmod +x recon-tool-linux-amd64
sudo mv recon-tool-linux-amd64 /usr/local/bin/recon-tool

# macOS AMD64
wget https://github.com/VOTRE_USERNAME/recon-tools/releases/latest/download/recon-tool-darwin-amd64
chmod +x recon-tool-darwin-amd64
sudo mv recon-tool-darwin-amd64 /usr/local/bin/recon-tool

# macOS ARM64 (M1/M2)
wget https://github.com/VOTRE_USERNAME/recon-tools/releases/latest/download/recon-tool-darwin-arm64
chmod +x recon-tool-darwin-arm64
sudo mv recon-tool-darwin-arm64 /usr/local/bin/recon-tool
```

### Compilation depuis les sources

```bash
git clone https://github.com/VOTRE_USERNAME/recon-tools.git
cd recon-tools
make build
sudo make install
```

## Utilisation

```bash
# Utilisation basique
recon-tool 10.10.10.1

# Avec une wordlist personnalisée
recon-tool example.com /path/to/wordlist.txt
```

## Fonctionnalités

L'outil exécute automatiquement les phases suivantes **en parallèle** :

1. **Scan initial** : `nmap <target>` - Scan rapide des ports courants
2. **Scan détaillé** : `nmap -A -p <ports_trouvés> <target>`
3. **Scan complet** : `nmap -p- <target>` - Scan de tous les ports
4. **Gobuster** : Si des services web sont détectés (ports 80, 443, 8080, 8443)
5. **Scan final** : `nmap -A -p <tous_les_ports> <target>` si de nouveaux ports sont trouvés

## Avantages

- ✅ **Non-bloquant** : Les scans s'exécutent en arrière-plan
- ✅ **Parallélisation** : Plusieurs scans simultanés
- ✅ **Logs détaillés** : Tous les résultats sont sauvegardés
- ✅ **Multi-format** : Sortie en texte et XML
- ✅ **Cross-platform** : Linux, macOS, Windows
- ✅ **Binaire unique** : Pas de dépendances

## Prérequis

- `nmap` installé
- `gobuster` installé (pour les scans web)

## Exemple de sortie

```
[15:30:15] Reconnaissance démarrée pour 10.10.10.1
[15:30:15] Résultats dans: recon_10.10.10.1_20231027_153015
[15:30:15] Phase 1: Scan initial des ports courants
[15:30:25] Terminé: Scan initial
[15:30:25] Ports ouverts trouvés: 22, 80, 443
[15:30:25] Phase 2: Scan détaillé des ports trouvés
[15:30:25] Phase 3: Scan complet de tous les ports
[15:30:25] Services web détectés, démarrage de gobuster
[15:30:25] Démarrage: Gobuster sur http://10.10.10.1
[15:30:25] Démarrage: Gobuster sur https://10.10.10.1
[15:32:18] Terminé: Scan détaillé des ports 22,80,443
[15:35:42] Terminé: Gobuster sur http://10.10.10.1
[15:36:12] Terminé: Gobuster sur https://10.10.10.1
[15:42:33] Terminé: Scan complet -p-
[15:42:34] 🎯 Reconnaissance terminée!
[15:42:34] 📁 Résultats dans: recon_10.10.10.1_20231027_153015
```

## Fichiers générés

- `01_initial_scan.txt` - Scan initial
- `02_detailed_scan.txt` - Scan détaillé des premiers ports
- `03_full_scan.txt` - Scan complet de tous les ports
- `04_final_detailed_scan.txt` - Scan final si nouveaux ports
- `gobuster_*.txt` - Résultats gobuster pour chaque service web
- `*.xml` - Versions XML des scans nmap
- `recon.log` - Log complet de la session

## Développement

```bash
# Compiler pour toutes les plateformes
make release

# Nettoyer
make clean

# Installer localement
make install
```