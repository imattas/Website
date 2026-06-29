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
  url: string;
  description: string;
  locale: string;
  themeColor: string;
  keywords: string[];
  author: {
    name: string;
    handle: string;
    role: string;
    email: string;
    sameAs: string[];
  };
  homeAsciiArt: string;
  homeSections: HomeSection[];
};

export const siteConfig: SiteConfig = {
  name: "imattas",
  url: "https://ianmattas.com/",
  description: "Ian Mattas - aspiring red teamer, pwn player, and security tooling builder.",
  locale: "en_US",
  themeColor: "#05070a",
  keywords: [
    "Ian Mattas",
    "imattas",
    "red team",
    "binary exploitation",
    "pwn",
    "CTF writeups",
    "security tooling",
    "Rust",
    "Gentoo",
    "low-level systems"
  ],
  author: {
    name: "Ian Mattas",
    handle: "imattas",
    role: "Aspiring red teamer and security tooling builder",
    email: "ian@mattas.net",
    sameAs: ["https://github.com/imattas", "https://linkedin.com/in/ian-mattas", "https://idktheflag.sh"]
  },
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
      title: "Contact",
      items: [
        {
          label: "github@plt",
          href: "https://github.com/imattas",
          external: true,
          prefix: "~ call"
        },
        {
          label: "email@plt",
          href: "mailto:ian@mattas.net",
          external: true,
          prefix: "~ call"
        },
        {
          label: "linkedin@plt",
          href: "https://linkedin.com/in/ian-mattas",
          external: true,
          prefix: "~ call"
        },
        {
          label: "about@local",
          href: "/volume/0/about/",
          prefix: "~ call"
        }
      ]
    }
  ]
};
