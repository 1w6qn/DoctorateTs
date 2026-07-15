import * as fs from 'fs';
import * as path from 'path';

const projectRoot = path.resolve(__dirname, '..');
const medalTablePath = path.join(projectRoot, 'data', 'excel', 'medal_table.json');
const medalTsPath = path.join(projectRoot, 'app', 'game', 'manager', 'medal.ts');

interface MedalData {
  medalId: string;
  medalName: string;
  template: string;
  unlockParam: string[];
  getMethod: string;
}

function loadMedalTemplates(): Set<string> {
  const data = JSON.parse(fs.readFileSync(medalTablePath, 'utf8'));
  const templates = new Set<string>();
  (data.medalList as MedalData[]).forEach(m => {
    if (m.template) {
      templates.add(m.template);
    }
  });
  return templates;
}

function loadExistingTemplates(): Set<string> {
  const code = fs.readFileSync(medalTsPath, 'utf8');
  const templates = new Set<string>();
  const methodRegex = /^\s+(\w+)\(args: \{/gm;
  let match;
  while ((match = methodRegex.exec(code)) !== null) {
    templates.add(match[1]);
  }
  return templates;
}

function generateTemplateMethod(templateName: string): string {
  const comment = `  /**
   * ${templateName}勋章模板
   * 追踪玩家在游戏中的相关行为
   */`;
  
  const method = `
  ${templateName}(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }`;
  
  return comment + method;
}

function insertTemplates(existingCode: string, newMethods: string[]): string {
  const insertPoint = '  toJSON(): PlayerPerMedal {';
  const insertIndex = existingCode.lastIndexOf(insertPoint);
  
  if (insertIndex === -1) {
    throw new Error('Cannot find insertion point');
  }
  
  return existingCode.slice(0, insertIndex) + newMethods.join('\n\n') + '\n\n' + existingCode.slice(insertIndex);
}

function main() {
  const excelTemplates = loadMedalTemplates();
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
  const existingCode = fs.readFileSync(medalTsPath, 'utf8');
  const newCode = insertTemplates(existingCode, newMethods);
  
  fs.writeFileSync(medalTsPath, newCode, 'utf8');
  console.log(`\nSuccessfully added ${missingTemplates.length} new medal template methods`);
}

main();
