import Link from "next/link";

export default function NotFound() {
  return (
    <section className="page-main d-grid align-items-center">
      <div className="container">
        <div className="error-wrap mx-auto">
          <div className="mb-3 fs-5 fw-bold">Bacha!</div>
          <h1 className="mb-3">404</h1>
          <p className="mb-4">Tahle stránka tu není.</p>
          <Link
            className="btn btn-bacha-secondary d-inline-flex align-items-center justify-content-center"
            href="/"
          >
            Zpět na hlavní stránku
          </Link>
        </div>
      </div>
    </section>
  );
}
