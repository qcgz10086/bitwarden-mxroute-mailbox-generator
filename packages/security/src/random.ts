const PREFIX = "23456789abcdefghjkmnpqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER = "abcdefghjkmnpqrstuvwxyz";
const DIGITS = "23456789";
const SYMBOLS = "!@#$%_-";
const PASSWORD = `${UPPER}${LOWER}${DIGITS}${SYMBOLS}`;

function randomIndex(length: number): number {
  const limit = Math.floor(256 / length) * length;

  while (true) {
    const byte = crypto.getRandomValues(new Uint8Array(1))[0]!;
    if (byte < limit) {
      return byte % length;
    }
  }
}

function randomCharacter(alphabet: string): string {
  return alphabet[randomIndex(alphabet.length)]!;
}

function shuffle(characters: string[]): void {
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    [characters[index], characters[swapIndex]] = [
      characters[swapIndex]!,
      characters[index]!,
    ];
  }
}

export function randomPrefix(length: number): string {
  return Array.from({ length }, () => randomCharacter(PREFIX)).join("");
}

export function randomMailboxPassword(): string {
  const characters = [
    randomCharacter(UPPER),
    randomCharacter(LOWER),
    randomCharacter(DIGITS),
    ...Array.from({ length: 15 }, () => randomCharacter(PASSWORD)),
  ];

  shuffle(characters);
  return characters.join("");
}

export function randomApiToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
