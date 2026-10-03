# prepublish-audit (Türkçe özet)

**Kod, site ya da paket şirketten çıkmadan önceki son kapı.** prepublish-audit; açık kaynak olarak
yayımlamak üzere olduğunuz bir depoyu, sitenin derleme çıktısını ya da paylaşacağınız bir zip dosyasını
yalnızca sizin bildiğiniz **gizli bir yasak listesiyle** (denylist), hazır gizli anahtar kalıplarıyla ve
sezgisel sızıntı kurallarıyla tarar. Dosya içeriklerine, dosya adlarına, ikili dosyalara, arşivlere,
görsel/PDF/Office/video üst verilerine ve **tüm git geçmişine** bakar. Bulduğu değeri, siz kendi
bilgisayarınızda `--reveal` demedikçe hiçbir yere yazmaz.

## Neler yakalar

- **Gizli yasak liste:** müşteri ve reklam hesabı kimlikleri, iç sunucu ve ürün adları, kişi adları,
  kart numaralarının son haneleri gibi size özel değerler. Liste deponun dışında durur ve raporlarda
  asla görünmez.
- **Gizli anahtarlar:** özel anahtarlar; AWS, GitHub, Google, Meta, Slack, Stripe, npm, PyPI, OpenAI ve
  Anthropic anahtarları; JWT'ler; URL içindeki parolalar. Kuruluysa gitleaks sonuçlarını da ekler.
- **Sezgisel kontroller:** ev dizini yolları (`/Users/<ad>`), e-postalar, uzun sayısal kimlikler, iç ağ
  IP adresleri ve sunucu adları, iç belge ve konsol bağlantıları, telefon ve kart numaraları, bulut ve
  reklam kimlikleri.
- **Üst veri:** EXIF yazar bilgisi ve GPS konumu, XMP, PDF ve Office yazar bilgileri ile belge
  özellikleri, video konum etiketleri.
- **Git geçmişi:** silinmiş dosyalar, yeniden adlandırılanlar dahil eski dosya adları, commit mesajları,
  yazar e-postaları, dal ve etiket adları.

Depodaki ayar dosyası herkese açıktır; yasak listeyi zayıflatamaz. Bu dosyada dışarıda bırakılan yollar
da yasak listeyle taranır, taramayı daraltan değerler ise uygulanmaz.

## Kurulum

Sıfırdan, adım adım rehber İngilizcedir ve yaklaşık 15 dakika sürer: [docs/setup.md](docs/setup.md).
Kısaca:

1. **Kurun.** Python 3.10 veya üstü yeterli:

   ```bash
   pipx install "git+https://github.com/deegitech/prepublish-audit@v0.1.0"
   ```

   İsteğe bağlı yardımcı araçlar daha fazlasını yakalar: `brew install gitleaks exiftool ffmpeg poppler`.

2. **Gizli listeyi oluşturun.** Yayımlayacağınız deponun klasörüne geçin (`cd ~/src/depom`) ve
   `prepublish-audit init` çalıştırın. `init`, depo klasörüne herkese açık ayar dosyasını
   (`.prepublish-audit.toml`; bunu commit'leyin), `~/.config/prepublish-audit/denylist.txt` yoluna da
   yalnızca sizin okuyabildiğiniz (600) bir liste şablonu yazar.

3. **Listeyi doldurun.** Dışarı çıkmaması gereken her değeri ayrı bir satıra yazın: hesap, kampanya
   ve reklam hesabı kimlikleri, bundle ID'ler, e-posta adresleri, sunucu ve bucket adları, kişi ve
   kullanıcı adları, ürün kod adları. En sağlam kaynak gerçek ayar dosyalarınız ve kayıtlarınızdır.
   `prepublish-audit check-denylist` yalnızca sayıları gösterir, girdileri hiçbir zaman yazmaz.

4. **Güvenli saklayın.** Dizüstü bilgisayarda varsayılan dosya (`chmod 600`) yeterli; tek şart,
   hiçbir git deposunun içinde durmaması. Listeyi macOS Anahtar Zinciri'nde tutmak isterseniz
   doldurduğunuz dosyayı tek komutla kaydedin:

   ```bash
   security add-generic-password -U -a "$USER" -s prepublish-audit-denylist \
     -w "$(base64 < ~/.config/prepublish-audit/denylist.txt)"
   ```

   Geri okumak için `~/.zshrc` dosyasına aşağıdaki yardımcıyı ekleyin, sonra yeni bir terminal açın
   (ya da `source ~/.zshrc` çalıştırın):

   ```bash
   pa_denylist() { security find-generic-password -a "$USER" -s prepublish-audit-denylist -w | base64 --decode; }
   ```

   `prepublish-audit check-denylist <(pa_denylist)` 3. adımdakiyle aynı sayıyı göstermeli. Sonra düz
   metin dosyayı silin (`rm ~/.config/prepublish-audit/denylist.txt`); silmezseniz taramalar ve
   kancalar eski kopyayı okumaya devam eder. Taramalarda `--require-denylist` kullanın: yardımcı yüklü
   değilse ya da anahtar zinciri kilitliyse `<(pa_denylist)` boş döner; bu seçenek sayesinde tarama
   sessizce geçmez, durur.

   `-w` değerini boş bırakmayın: macOS parolayı sorar ve 128 karakterden sonrasını sessizce keser
   (Ekim 2026'da gözlendi). Panodan kaydetmek de mümkün (`-w "$(pbpaste | base64)"`), ama pano
   yöneticileri geçmiş tutar, Evrensel Pano da içeriği diğer Apple aygıtlarınıza taşır. CI'da listeyi
   GitHub'da bir ortamın (environment) gizli değeri olarak, sunucularda AWS SSM SecureString olarak
   saklayın.

5. **Kontrol edin.** Aynı klasörde `prepublish-audit doctor` çalıştırın (liste Anahtar Zinciri'ndeyse
   `prepublish-audit doctor --denylist <(pa_denylist)`). Her maddeyi ✓ ya da ✗ ile gösterir ve ✗ olan
   her maddenin altına ne yapmanız gerektiğini yazar. Her şey yolundaysa 0 koduyla çıkar ve son
   satırda çalıştırmanız gereken tarama komutunu verir.

6. **İlk taramayı yapın.** `prepublish-audit scan --git-files --history .` Tarama hiçbir dosyayı
   değiştirmez. Eşleşmeleri görmek için yalnızca kendi bilgisayarınızda `--reveal` ekleyin.

7. **Kancaları kurun.** [examples/pre-commit-config.yaml](examples/pre-commit-config.yaml) içeriğini
   `.pre-commit-config.yaml` dosyanıza ekleyin, sonra `pre-commit install` ve
   `pre-commit install --hook-type pre-push` çalıştırın. İkincisi en çok unutulan adımdır; o olmadan
   geçmişi tarayan kanca hiç çalışmaz. Kancalar kabuk fonksiyonlarınızı göremez, listeyi varsayılan
   dosyadan ya da `PREPUBLISH_AUDIT_DENYLIST` değişkeninden okur. Liste yalnızca Anahtar
   Zinciri'ndeyse [rehberin 7. adımındaki](docs/setup.md#step-7-run-it-automatically-once-per-repository)
   yerel kancayı kullanın.

8. **Depoyu herkese açmadan önce** commit e-postası, gizli anahtar taraması, push koruması, dal
   koruması ve iki adımlı doğrulama gibi GitHub ayarlarını
   [rehberin 8. adımına](docs/setup.md#step-8-before-the-repository-goes-public-once-per-repository)
   göre yapın.

Bir hata aldığınızda araç, hatanın hemen altına çözümünü de yazar (`prepublish-audit: fix: ...`).
Bütün hata mesajları ve çözümleri: [docs/troubleshooting.md](docs/troubleshooting.md).

Çıkış kodları: `0` temiz, `1` bulgu var, `2` hata. Ayrıntılı belgeler İngilizcedir:
[README.md](README.md), kural listesi [docs/rules.md](docs/rules.md), yayın öncesi kontrol listesi
[docs/release-checklist.md](docs/release-checklist.md).

## Lisans

[MIT](LICENSE) © 2026 DEEGITECH Teknoloji ve Yazılım Ltd. Şti.
