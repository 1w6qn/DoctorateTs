import * as fs from 'fs';
import * as path from 'path';

const projectRoot = path.resolve(__dirname, '..');
const missionTablePath = path.join(projectRoot, 'data', 'excel', 'mission_table.json');
const missionTsPath = path.join(projectRoot, 'app', 'game', 'manager', 'mission.ts');

interface MissionData {
  id: string;
  template: string;
  param: string[];
  description: string;
}

function loadMissionTemplates(): Set<string> {
  const data = JSON.parse(fs.readFileSync(missionTablePath, 'utf8'));
  const templates = new Set<string>();
  Object.values(data.missions as { [key: string]: MissionData }).forEach(m => {
    if (m.template) {
      templates.add(m.template);
    }
  });
  return templates;
}

function loadExistingTemplates(): Set<string> {
  const code = fs.readFileSync(missionTsPath, 'utf8');
  const templates = new Set<string>();
  const lines = code.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^\s+(\w+): \{/);
    if (match) {
      const key = match[1];
      if (!key.startsWith('_') && !key.match(/^\d+$/)) {
        templates.add(key);
      }
    }
  }
  
  return templates;
}

function generateTemplateMethod(templateName: string): string {
  return `
  ${templateName}: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
  },`;
}

function insertTemplates(existingCode: string, newMethods: string[]): string {
  const insertPoint = '};';
  const lines = existingCode.split('\n');
  
  let insertIndex = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].trim() === insertPoint) {
      insertIndex = i;
      break;
    }
  }
  
  if (insertIndex === -1) {
    throw new Error('Cannot find insertion point');
  }
  
  return lines.slice(0, insertIndex).join('\n') + newMethods.join('\n') + '\n' + lines.slice(insertIndex).join('\n');
}

function main() {
  const excelTemplates = loadMissionTemplates();
  const existingTemplates = loadExistingTemplates();
  
  const missingTemplates = Array.from(excelTemplates).filter(t => !existingTemplates.has(t)).sort();
  
  console.log(`Total templates in excel: ${excelTemplates.size}`);
  console.log(`Total templates in code: ${existingTemplates.size}`);
  console.log(`Missing templates: ${missingTemplates.length}`);
  
  if (missingTemplates.length === 0) {
    console.log('All templates are already implemented');
    return;
  }
  
  console.log('\nMissing templates:');
  missingTemplates.forEach(t => console.log(`  ${t}`));
  
  const newMethods = missingTemplates.map(t => generateTemplateMethod(t));
  const existingCode = fs.readFileSync(missionTsPath, 'utf8');
  const newCode = insertTemplates(existingCode, newMethods);
  
  fs.writeFileSync(missionTsPath, newCode, 'utf8');
  console.log(`\nSuccessfully added ${missingTemplates.length} new mission template methods`);
}

main();
