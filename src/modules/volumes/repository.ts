import { volumeConfig } from "../../config";
import type { Phile } from "../philes/model";
import { getAllPhiles, getPhilesByVolume } from "../philes/repository";
import type { Volume } from "./model";

export async function getAllVolumes(philes?: Phile[]): Promise<Volume[]> {
  const allPhiles = philes ?? (await getAllPhiles());
  const philesByVolume = new Map<number, Phile[]>();

  for (const phile of allPhiles) {
    const volumePhiles = philesByVolume.get(phile.route.volume);

    if (volumePhiles) {
      volumePhiles.push(phile);
    } else {
      philesByVolume.set(phile.route.volume, [phile]);
    }
  }

  return [...philesByVolume.entries()]
    .sort(([left], [right]) => compareVolumes(left, right))
    .map(([number, volumePhiles]) => {
      const philes = tocPhiles(number, volumePhiles);

      return {
        number,
        href: `/volume/${number}/`,
        philes,
        displayCount: displayCount(number, volumePhiles, philes)
      };
    })
    .filter((volume) => volume.philes.length > 0);
}

function compareVolumes(left: number, right: number): number {
  return left - right;
}

export async function getVolume(number: number): Promise<Volume | undefined> {
  const volumePhiles = await getPhilesByVolume(number);
  const philes = tocPhiles(number, volumePhiles);

  if (philes.length === 0) {
    return undefined;
  }

  return {
    number,
    href: `/volume/${number}/`,
    philes,
    displayCount: displayCount(number, volumePhiles, philes)
  };
}

function tocPhiles(number: number, philes: Phile[]): Phile[] {
  const kind = volumeConfig(number).tocWriteupKind;

  if (!kind) {
    return philes;
  }

  return philes.filter((phile) => phile.data.writeupKind === kind);
}

function displayCount(number: number, allPhiles: Phile[], tocEntries: Phile[]): number {
  const kind = volumeConfig(number).countWriteupKind;

  if (!kind) {
    return tocEntries.length;
  }

  return allPhiles.filter((phile) => phile.data.writeupKind === kind).length;
}
