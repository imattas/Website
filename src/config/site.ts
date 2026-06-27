export type HomeItem = {
  label: string;
  href?: string;
  linkLabel?: string;
  external?: boolean;
  prefix?: string;
};

export type HomeSection = {
  title: string;
  items?: HomeItem[];
  volumes?: {
    include?: number[];
    exclude?: number[];
    sort?: "asc" | "desc";
    showEmpty?: boolean;
  };
};

export type SiteConfig = {
  name: string;
  description: string;
  homeAsciiArt: string;
  homeSections: HomeSection[];
};

export const siteConfig: SiteConfig = {
  name: "imattas",
  description: "Ian Mattas - aspiring red teamer, pwn player, and security tooling builder.",
  homeAsciiArt: `██╗███╗   ███╗ █████╗ ████████╗████████╗ █████╗ ███████╗
██║████╗ ████║██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝
██║██╔████╔██║███████║   ██║      ██║   ███████║███████╗
██║██║╚██╔╝██║██╔══██║   ██║      ██║   ██╔══██║╚════██║
██║██║ ╚═╝ ██║██║  ██║   ██║      ██║   ██║  ██║███████║
╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝`,
  homeSections: [
    {
      title: "TL;DR",
      items: [
        {
          label: "Ian Mattas / imattas"
        },
        {
          label: "Aspiring red teamer focused on pwn, security tooling, and CTF infrastructure."
        },
        {
          label: "Doing pwn for @idktheflag",
          linkLabel: "@idktheflag",
          href: "https://github.com/idktheflag",
          external: true
        },
        {
          label: "Founder of @redsecc",
          linkLabel: "@redsecc",
          href: "https://github.com/redsecc",
          external: true
        },
        { label: "About", href: "/volume/0/about/" }
      ]
    },
    {
      title: "Index",
      volumes: {
        sort: "asc",
        showEmpty: false
      }
    },
    {
      title: "Projects",
      items: [
        {
          label: "All public GitHub repos rendered from their README files.",
          href: "/volume/1/"
        },
        {
          label: "Writeups - CTF and cybersecurity notes.",
          href: "/volume/2/"
        }
      ]
    },
    {
      title: "Contact",
      items: [
        {
          label: "github@plt",
          href: "https://github.com/imattas",
          external: true,
          prefix: "~ call"
        },
        {
          label: "web@plt",
          href: "https://ianmattas.com",
          external: true,
          prefix: "~ call"
        },
        {
          label: "links@local",
          href: "/volume/0/about/",
          prefix: "~ call"
        }
      ]
    }
  ]
};
