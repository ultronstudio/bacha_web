type IconName =
  | "moon-stars"
  | "sun"
  | "list"
  | "link-45deg"
  | "image"
  | "qr-code-scan"
  | "telephone"
  | "chevron-right"
  | "shield-check"
  | "exclamation-triangle"
  | "lock"
  | "check-lg";

export function Icon({
  name,
  className = "",
}: {
  name: IconName;
  className?: string;
}) {
  return (
    <svg className={`bs-icon ${className}`.trim()} aria-hidden="true">
      <use href={`/assets/images/${name}.svg#icon`} />
    </svg>
  );
}
