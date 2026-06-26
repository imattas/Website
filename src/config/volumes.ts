export type VolumePhileSort = {
  by: "date" | "order";
  direction: "asc" | "desc";
};

export type VolumeConfig = {
  title: string;
  subtitle?: string;
  listLabel: string;
  postscript?: string[];
  entryPrefix?: string;
  entryLabel?: "index" | "year";
  reverseEntryNumbers?: boolean;
  phileSort?: VolumePhileSort;
  tocWriteupKind?: "root" | "template" | "ctf" | "challenge";
  countWriteupKind?: "root" | "template" | "ctf" | "challenge";
};

export const defaultVolumeConfig = (number: number): VolumeConfig => ({
  title: `imattas Volume ${number}`,
  listLabel: `Volume ${number}`,
  phileSort: {
    by: "date",
    direction: "desc"
  },
  postscript: ["  ──[ EOF ]──────────────────────────────────────────────────────────────────//───"]
});

export const volumeConfigs = new Map<number, VolumeConfig>([
  [
    0,
    {
      title: "Profile",
      listLabel: "Volume 0 - Profile",
      phileSort: {
        by: "order",
        direction: "asc"
      },
      postscript: [
        "  --[ EOF ]-------------------------------------------------------------//---",
        "",
        "  profile loaded"
      ],
      entryPrefix: "P"
    }
  ],
  [
    1,
    {
      title: "Projects",
      listLabel: "Volume 1 - Projects",
      postscript: [
        "  --[ EOF ]-------------------------------------------------------------//---",
        "",
        "  source available on github.com/imattas"
      ],
      phileSort: {
        by: "order",
        direction: "asc"
      },
      entryPrefix: "X"
    }
  ],
  [
    2,
    {
      title: "Writeups",
      listLabel: "Volume 2 - Writeups",
      postscript: [
        "  --[ EOF ]-------------------------------------------------------------//---",
        "",
        "  imported from github.com/imattas/Writeups as checked-in MDX"
      ],
      phileSort: {
        by: "order",
        direction: "asc"
      },
      tocWriteupKind: "ctf",
      countWriteupKind: "challenge",
      entryPrefix: "W"
    }
  ]
]);

export function volumeConfig(number: number): VolumeConfig {
  return volumeConfigs.get(number) ?? defaultVolumeConfig(number);
}
