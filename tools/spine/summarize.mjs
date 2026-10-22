// node summarize.mjs <dir>...: for every Spine binary skeleton (*.skel, *.skel.bytes) under the dirs,
// write <file>.spine.txt beside it: version, fps, bones, slots, skins, events, and per animation the
// duration plus each event key with its time. No atlas needed: attachments are stubbed.
import fs from 'fs';
import path from 'path';
import * as spine from './node_modules/@esotericsoftware/spine-core/dist/index.js';

const stub = {
  newRegionAttachment: (skin, name, p) => { const a = new spine.RegionAttachment(name, p); a.updateRegion = () => {}; return a; },
  newMeshAttachment: (skin, name, p) => { const a = new spine.MeshAttachment(name, p); a.updateRegion = () => {}; return a; },
  newBoundingBoxAttachment: (skin, name) => new spine.BoundingBoxAttachment(name),
  newPathAttachment: (skin, name) => new spine.PathAttachment(name),
  newPointAttachment: (skin, name) => new spine.PointAttachment(name),
  newClippingAttachment: (skin, name) => new spine.ClippingAttachment(name),
};

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (/\.skel(\.bytes)?$/i.test(e.name)) yield p;
  }
}

let ok = 0, bad = 0;
for (const root of process.argv.slice(2)) {
  for (const file of walk(root)) {
    try {
      const data = new spine.SkeletonBinary(stub).readSkeletonData(new Uint8Array(fs.readFileSync(file)));
      const lines = [
        `spine ${data.version} fps ${data.fps} bones ${data.bones.length} slots ${data.slots.length}`,
        `skins: ${data.skins.map(s => s.name).join(', ')}`,
        `events: ${data.events.map(e => `${e.name}(int=${e.intValue} float=${e.floatValue} string=${e.stringValue ?? ''})`).join(', ')}`,
        `animations (${data.animations.length}):`,
      ];
      for (const a of data.animations) {
        const keys = [];
        for (const t of a.timelines) {
          if (t instanceof spine.EventTimeline) for (const ev of t.events) keys.push(`${ev.data.name}@${ev.time.toFixed(3)}`);
        }
        lines.push(`  ${a.name}  ${a.duration.toFixed(3)}s${keys.length ? '  events: ' + keys.join(' ') : ''}`);
      }
      fs.writeFileSync(file + '.spine.txt', lines.join('\n') + '\n');
      ok++;
    } catch (e) {
      fs.writeFileSync(file + '.spine.txt', `unreadable: ${e.message}\n`);
      bad++;
    }
  }
}
console.log(`spine summaries: ${ok} ok, ${bad} unreadable`);
