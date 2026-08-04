# Maintainer: bermudi
pkgname=aur-gate-git
pkgver=0.1.0.r0.g0000000
pkgrel=1
pkgdesc='Deterministic pre-install gate for Arch Linux AUR updates'
arch=('x86_64')
url='https://github.com/bermudi/aur-gate'
license=('MIT')
depends=('curl' 'git' 'less' 'pacman' 'util-linux')
makedepends=('cargo' 'git')
checkdepends=('zsh')
optdepends=('yay: supported AUR helper' 'paru: supported AUR helper')
provides=('aur-gate')
conflicts=('aur-gate')
source=('aur-gate::git+https://github.com/bermudi/aur-gate.git#branch=main')
sha256sums=('SKIP')

pkgver() {
  cd aur-gate
  git describe --long --tags 2>/dev/null \
    | sed 's/^v//;s/-/.r/;s/-/./' \
    || printf '0.1.0.r%s.g%s\n' "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

prepare() {
  cd aur-gate
  cargo fetch --locked
}

build() {
  cd aur-gate
  cargo build --frozen --release
}

check() {
  cd aur-gate
  cargo test --frozen --all-targets
  cargo run --frozen --quiet -- selftest
  bash -n assets/wrapper.sh
  zsh -n assets/wrapper.sh
}

package() {
  cd aur-gate
  install -Dm755 target/release/aur-gate "$pkgdir/usr/bin/aur-gate"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 docs/design-ledger.md \
    "$pkgdir/usr/share/doc/$pkgname/design-ledger.md"
}
