# mcp-argguard

MCP için savunma amaçlı bir çalışma zamanı politika vekili. İstemci ile sunucu arasında stdio üzerinde durur ve `tools/call` çağrılarına araç bazında argüman politikası uygular.

**mcp-argguard bir savunma kontrol katmanıdır; bir güvenlik garantisi değildir ve bir istismar aracı değildir. Yalnızca korumaya yetkili olduğunuz MCP istemcilerinde ve sunucularında kullanın. Saldırı yükü taşımaz ve yamanın yerini tutmaz: etkilenen sunucuları güncelleyin.**

Aynı uyarı `mcp-argguard --help` çıktısında ve `wrap` başlangıç bandında (stderr) basılır. Ayrıntı için [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).

Bu paket npm'e veya başka bir kayıt defterine yayımlanmaz. `npm publish` kapalıdır. Kurulum bir git kopyasından yapılır; CLI derlenmiş hâlinden çalıştırılır.

## v0.1

v0.1 yalnızca stdio'dur. Çekirdek, MCP SDK'sının üst düzey sunucu katmanı değil, satır satır JSON-RPC rölesidir. Böylece 2025-11-25 `initialize` el sıkışması da durumsuz 2026-07-28 trafiği de geçer. SDK yalnızca tipler, sahte sunucular ve testler için bir geliştirme bağımlılığıdır.

Bu sürümde:

- `tools/call`, seçilen sunucu profilinde eşleşen bir araç kuralı varsa izinlidir. Bilinmeyen aracın varsayılanı reddetmektir. Kuralın anmadığı argümanın varsayılanı reddetmektir.
- `mode: enforce` reddedilen satırı çocuğa yazmaz ve bir JSON-RPC hatası döner. `mode: monitor` aynı reddi günlüğe yazar ve satırı yine iletir.
- Ana makine adı, URL ve dosya yolu kuralları değeri önce normalleştirir, sonra karşılaştırır. Ham metin üzerinde salt regex değillerdir.
- Gizli kalıp eşleşmeleri (özel anahtar başlığı, erişim anahtarı biçimi, `.env` yolları) çağrıyı reddedebilir.
- Kararlar `0600` kipinde bir JSONL günlüğüne eklenir.
- `validate`, `test` ve `explain` bir sunucu başlatmadan politikayı inceler.
- Başlatma sınıflandırıcısı `npx -c` ve `node -e` gibi gömülü kod bayraklarını tanır. `wrap` bunu v0.3'e kadar uygulamaz. Uyarı basar ve çocuğu yine başlatır.

Streamable HTTP v0.2'dir. Başlatma korumasının uygulanması ve `lint-config` v0.3'tür. Korumalı alan (sandbox) ve LLM ile enjeksiyon tespiti kapsam dışıdır. Bakınız [docs/architecture.md](docs/architecture.md) ve [docs/threat-model.md](docs/threat-model.md).

## Gereksinimler

Node.js 24 LTS veya daha yenisi. CLI daha eski Node sürümlerinde çıkar.

## Kurulum

```sh
git clone https://github.com/alikesk222/mcp-argguard.git
cd mcp-argguard
npm ci --ignore-scripts
npm run build
node dist/cli/main.js --help
```

## Hızlı başlangıç

Bir başlangıç politikasını denetleyin, sonra motora tek bir çağrı sorun. `explain` hem izin hem ret için 0 ile çıkar ve kararı basar.

```sh
node dist/cli/main.js validate --policy policies/starter/filesystem.yaml --strict
node dist/cli/main.js explain \
  --policy policies/starter/filesystem.yaml \
  --server filesystem \
  --tool read_file \
  --args "{\"path\":\"/tmp/not-in-the-workspace\"}"
```

CVE sınıfı vakalarını çalıştırın. Soket açmazlar ve sınıflandırılan başlatma komutlarını çalıştırmazlar.

```sh
node dist/cli/main.js test \
  --policy policies/cve-classes/cve-2026-18655.yaml \
  --cases policies/cve-classes/cve-2026-18655.cases.yaml
```

Yetkili olduğunuz bir sunucuyu sarın. `--` sonrasındaki her şey çocuk süreçtir (`shell: false`). Vekil bandı stderr'e yazılır.

```sh
node dist/cli/main.js wrap \
  --policy policies/starter/filesystem.yaml \
  --server filesystem \
  --workspace "$PWD" \
  --log "$PWD/.argguard/decisions.jsonl" \
  -- node /path/to/your-mcp-server.js
```

İstemci yapılandırması `command` olarak Node'u ve bu CLI'yi gösterir; asıl sunucu ancak ondan sonra gelir:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": [
        "/absolute/path/to/mcp-argguard/dist/cli/main.js",
        "wrap",
        "--policy",
        "/absolute/path/to/mcp-argguard/policies/starter/filesystem.yaml",
        "--server",
        "filesystem",
        "--workspace",
        "/absolute/path/to/the/project",
        "--",
        "node",
        "/absolute/path/to/your-mcp-server.js"
      ]
    }
  }
}
```

## Politika örneği

`mode` zorunludur. Bilinmeyen araçlar ve bilinmeyen argümanlar varsayılan olarak reddedilir. `${workspace}` yol köklerinde açılır, argüman değerlerinde açılmaz. Alan listesinin tamamı [docs/policy-reference.md](docs/policy-reference.md) dosyasındadır. Birleşik bir örnek [policies/examples/policy.example.yaml](policies/examples/policy.example.yaml) dosyasındadır.

```yaml
version: 1
mode: enforce
defaults:
  tool: deny
  unknown_args: deny
log:
  path: ~/.argguard/decisions.jsonl
  store_args: hashed
servers:
  filesystem:
    tools:
      read_file:
        decision: allow
        args:
          path:
            type: path
            within: ["${workspace}"]
            deny: ["**/.env*", "**/.ssh/**", "**/*.pem", "**/*.key"]
            resolve_symlinks: true
      "delete_*":
        decision: deny
        reason: "deletion is disabled in this profile"
```

Başlangıç profilleri: [policies/starter/filesystem.yaml](policies/starter/filesystem.yaml), [policies/starter/fetch.yaml](policies/starter/fetch.yaml), [policies/starter/shell.yaml](policies/starter/shell.yaml).

## CVE sınıfı paketler

Her paket bir sınır örneği ve bir regresyon korpusudur. Testler yalnızca yerel sahte MCP sunucularını kullanır. İstismar metni içermezler ve ağa çıkmazlar.

### CVE-2026-18655

Amazon MQ MCP ana makine adı üzerinden kimlik bilgisi sızıntısı, 2.0.24 öncesi. [GHSA-xwj6-8x5h-hjp6](https://github.com/advisories/GHSA-xwj6-8x5h-hjp6), [AWS bülteni 2026-070](https://aws.amazon.com/security/security-bulletins/2026-070-aws/). Politika: [cve-2026-18655.yaml](policies/cve-classes/cve-2026-18655.yaml).

Bülten metni `broker_hostname` parametresini ve `rabbimq_broker_initialize_connection` ile `rabbimq_broker_initialize_connection_with_oauth` araçlarını adlandırır (yayımlanmış yazım). Bu depo o sunucuyu içermez ve şemasını yeniden ayrıştırmamıştır. `b-*.mq.eu-central-1.amazonaws.com` izin listesi tek bir bölge için örnektir; her Amazon MQ uç noktasının bu biçimde olduğu iddiası değildir. Satıcının geçici çözüm örneği `<broker_id>.mq.<region>.on.aws` biçimindedir. Plan taslağındaki `connect` yer tutucu adı bültende yoktur ve reddedilir.

### CVE-2026-75130

Context7, bir kodlama ajanının uyabileceği özel talimat metnini sunuyordu. Satıcı 2026-02-23'te sunucu tarafı bir düzeltme bildirdi. Politika: [cve-2026-75130.yaml](policies/cve-classes/cve-2026-75130.yaml).

Paket talimat metnini tespit etmez. Sonraki çağrıları sınırlar: `read_file` çalışma alanının içinde kalır ve `.env` / anahtar yollarına girmez, `fetch` bir HTTPS ana makine izin listesinde kalır, `delete_*` reddedilir. Sahte `get_docs` aracı zararsız bir cümle döner. Test istemcisi takip çağrılarını kendisi gönderir.

### CVE-2026-40933

Flowise 3.1.0 öncesi, satır içi kod bayrağı da alan izinli stdio komutlarını kabul ediyordu. [GHSA-c9gw-hvqq-f33r](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-c9gw-hvqq-f33r). Politika: [cve-2026-40933.yaml](policies/cve-classes/cve-2026-40933.yaml).

Paket bir bayrak red listesidir (`npx -c` / `--call`, `node -e` / `--eval` / `-p`, `python -c`, `python3 -c`, `bash -c`, `sh -c`). Listede olmayan bir komut güvenlik iddiası değildir. Vakalar etkisiz `marker` simgesini kullanır ve süreç başlatmaz. `wrap` bu bölümü v0.3'e kadar uygulamaz.


## Karşılaştırma

Argüman düzeyinde politikası olan açık kaynak MCP vekilleri zaten var. mcp-argguard onların yerine geçmez. En yakını [MCP Shield Runtime](https://github.com/samsgates/mcp-shield-runtime): stdio ve Streamable HTTP, yol kuralları, gizli yollar, metadata URL'leri, onay akışı ve şema kilit dosyası. Bu projenin v0.1 sürümü daha küçük bir stdio rölesidir.

Ayrım şunlardadır: CVE'ye bağlı paketler ve onların sahte sunucu regresyon testleri; normalleştirmeye dayanan ana makine adı, URL ve yol denetimleri; gömülü kod bayrakları için v0.3 başlatma koruması. PolicyLayer Intercept, mcp-policy-gateway, mcp-airlock, mcp-context-protector, docker/mcp-gateway ve sparfenyuk/mcp-proxy'yi de içeren tablo [docs/comparison.md](docs/comparison.md) dosyasındadır.

## Yol haritası

| Sürüm          | İçerik                                                                                                                                                                                      |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| v0.1 (bu ağaç) | stdio rölesi, `tools/call` politikası, enforce ve monitor, JSONL günlüğü, `validate` / `test` / `explain`, üç CVE sınıfı paket, başlatma sınıflandırıcısı yalnızca `test` ve `explain` için |
| v0.2           | Streamable HTTP ters vekili                                                                                                                                                                 |
| v0.3           | Başlatma korumasını `wrap` içinde uygulamak. `lint-config`, vekilden geçmeyen bir MCP istemci yapılandırmasını raporlar                                                                     |

Çocuk süreci korumalı alana almak ve istem enjeksiyonunu bir modelle tespit etmek kapsam dışıdır.

## Geliştirme

```sh
npm test          # derle, sonra birim + entegrasyon + fuzz + regresyon
npm run lint      # biome ci
npm run typecheck
npm run test:fuzz # daha uzun özellik koşusu
```

GitHub Actions üzerindeki CI, Node.js 24 (Ubuntu) ile lint, tip denetimi ve testi çalıştırır. Haftalık bir iş akışı özellik testlerini yineler. Sürüm yayımlama iş akışı yoktur.

## Lisans

[MIT](LICENSE). Telif hakkı 2026 Ali Kesik.

[Güvenlik bildirimleri](SECURITY.md) · [Katkı](CONTRIBUTING.md) · [Davranış kuralları](CODE_OF_CONDUCT.md)
