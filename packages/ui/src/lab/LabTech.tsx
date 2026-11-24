import type {ReactNode} from "react";

// Stand-in for `<Tech>` of packages/ui/src/data/Tech.tsx, which is WP7's file and
// does not exist yet. Same contract (spec 2.2 and ctrlz-frontend: domains, IPs and
// other technical tokens render as `<bdi dir="ltr">`, so they keep their order
// inside a Persian sentence). When WP7 lands, change the import in the lab files
// and delete this one.

export function Tech({children, className}: {children: ReactNode; className?: string}) {
  return (
    <bdi dir="ltr" className={["font-mono", className].filter(Boolean).join(" ")}>
      {children}
    </bdi>
  );
}
