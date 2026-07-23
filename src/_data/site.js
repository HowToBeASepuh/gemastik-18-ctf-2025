import fs from "node:fs";

let description = "";
try {
  description = fs.readFileSync("./description.txt", "utf-8").trim();
} catch {
  description = "";
}

export default {
  title: "Gemastik XVIII CTF 2025",
  team: "HowToBeASepuh",
  event: "GEMASTIK 18 — Cyber Security Division",
  institution: "Institut Teknologi Bandung",
  description,
  descriptionEn:
    "GEMASTIK 18 (Pagelaran Mahasiswa Nasional Bidang Teknologi Informasi dan Komunikasi) is Indonesia's national ICT competition for university students, organized by the National Achievement Center of the Ministry of Higher Education, Science and Technology. It spans branches such as programming, cyber security, data mining, UX design, animation, smart city, scientific writing, software development, intelligent devices & IoT, game development, and ICT business development — a venue for collaboration, innovation, and real student contribution to ICT-based solutions.",
  intro:
    "HowToBeASepuh's write-ups for the Cyber Security (CTF) division of GEMASTIK 18, split into the Qualifications and Finals rounds.",
  repo: "https://github.com/HowToBeASepuh/gemastik-18-ctf-2025",
};
