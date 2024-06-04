#! /usr/bin/env node
const fs = require('fs'); // needed for reading & writing to files
const mustache = require('mustache'); // needed for rendering templates
const path = require('path');

/*
  viewBom
  by Evan X. Merz
  https://www.npmjs.com/package/viewbom

  viewBom is a dead simple package for converting a cyclonedx 
  software bill of materials into an html file. It also does
  a small amount of analysis.

  It exports three methods:
  1. analyze = analyzes a clyclonedx sbom as json
  2. renderToHtml = renders the analysis to an html string
  3. viewBom = run both of the above methods and save to a file

  For more about cyclonedx bill of materials,
  see https://www.npmjs.com/package/@cyclonedx/bom

  For more about mustache templating,
  see https://www.npmjs.com/package/mustache
*/

const analyze = (bom) => {
  const analysis = [];
  const licenseMap = new Map();
  const linkMap = new Map();
  
  for(const component of bom.components) {
    
    const licenses = component.licenses;
    let licenseString = '';
    if (licenses) {
      const licenseArray = [];
      licenses.forEach(lic => {
        if (lic.license && lic.license.id) {
          licenseArray.push(lic.license.id);
          licenseMap.set(lic.license.id, lic.license.id);
        }
      });

      licenseString = licenseArray.join(', ');
    }
    
    const extRefs = component.externalReferences;
    if (extRefs) {
      let linkMapKey = 1;
      for (const ref of extRefs) {
        if (ref.type) {
          linkMap.set(ref.type, ref.type);
        } else {
          linkMap.set('Link' + linkMapKey, 'Link' + linkMapKey);
          linkMapKey++;
        }
      }
    }

    analysis.push({ 
      name: component.name, 
      version: component.version,
      description: component.description,
      licenses: licenseString,
      externalReferences: extRefs });
  }

  const lic = [];
  for (const kv of licenseMap) {
    lic.push(kv[0]);
  }

  const refs = [];
  for (const kv of linkMap) {
    refs.push(kv[0]);
  }

  // returned the analyzed bom
  return { licenses: lic, links: refs, components: analysis };
};


const renderToHtml = (analysis, templatePath) => {
  const template = fs.readFileSync(templatePath, 'utf8');
  const output = mustache.render(template, analysis);
  return output;
};

const renderToCsv = (analysis, templatePath) => {
  const template = fs.readFileSync(templatePath, 'utf8');
  const config = {};
  // to escape commas in CSV, we need to do 2 things -
  // 1. enclose the text in double quotes
  // 2. escape any double quotes in the text itself with 2 double quotes
  config.escape = s => {
    if (s) {
      s = s.replaceAll('"', '""');
      return '"' + s + '"';
    }
    else {
      return s;
    }
  };
  const output = mustache.render(template, analysis, null, config);
  return output;
};

const getOutputFile = (inputFile, ext) => {
  const xt = path.extname(inputFile); // should return the file extension
  if (xt.length > 0) { // if there is an extension, replace it with the 'ext' param's value
    return inputFile.replaceAll(xt, ext);
  }
  else { // else the file has no extension, so append the 'ext' param's value
    return inputFile + ext;
  }
};

const viewBom = (inputFilePath, outputFilePath) => {
  // get the arguments
  const args = process.argv.slice(2);
  const inputFile = inputFilePath || args[0] || null;
  if (!inputFile) {
    throw new Error('Usage: viewBom <inputBomFileInJson> <outputFileInHtml>'); 
  }

  let outputFile = outputFilePath || args[1] || null;

  if (!outputFile) {
    outputFile = getOutputFile(inputFile, '.html');
    console.log('HTML output file will be written to: ' + outputFile);
  }

  // read the json in the input file
  const rawdata = fs.readFileSync(inputFile);
  const bom = JSON.parse(rawdata);

  const analysis = analyze(bom);
  const html = renderToHtml(analysis, `${__dirname}/../templates/page.html`);

  // write to a file
  fs.writeFileSync(outputFile, html);

  outputFile = getOutputFile(inputFile, '.csv');
  console.log('CSV output file will be written to: ' + outputFile);
  const csv = renderToCsv(analysis, `${__dirname}/../templates/out.csv`);
  fs.writeFileSync(outputFile, csv);

  process.exit(0);
};

module.exports = [
  analyze,
  renderToHtml,
  viewBom,
];

// If called using npx, then run viewBom. Otherwise, do nothing
// See https://stackoverflow.com/questions/6398196/detect-if-called-through-require-or-directly-by-command-line
if (require.main === module) {
  viewBom();
}

