import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Hackapol · Centro de operaciones",
  description: "Clasificación de incidentes SOC y contención autorizada del equipo 2.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es">
      <body className="antialiased">{children}</body>
    </html>
  );
}
