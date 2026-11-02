import { Icon } from "@/components/Icon";

export default function NoticeBanner() {
  return (
    <aside className="site-notice" aria-label="Důležité upozornění">
      <div className="container">
        <div className="site-notice-inner">
          <Icon name="exclamation-triangle" className="site-notice-icon" />
          <div className="site-notice-copy">
            <p className="mb-1">
              Zařazení do uzavřeného testování může chvíli trvat, každou přihlášku
              ručně kontrolujeme.
            </p>
            <p className="mb-0">
              Řešíte-li něco akutně, obraťte se přímo na příslušnou oficiální
              instituci, například Policii ČR, svou banku nebo pojišťovnu.
            </p>
          </div>
        </div>
      </div>
    </aside>
  );
}
