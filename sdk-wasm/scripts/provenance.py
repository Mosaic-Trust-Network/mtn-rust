"""Record immutable build inputs and output hashes without publishing artifacts."""
import hashlib,json,os,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
repo=root.parent
paths=[repo/'Cargo.toml',repo/'Cargo.lock',root/'Cargo.toml',root/'package.json',root/'package-lock.json',root/'tsconfig.json']
paths.extend(sorted((root/'src').rglob('*.rs')))
paths.extend(sorted((root/'typescript').rglob('*.*')))
paths.extend(sorted((root/'scripts').glob('*')))
paths.extend(sorted(p for p in (root/'tests').rglob('*') if p.is_file()))
paths.extend(sorted((root/'generated/node').glob('*')))
paths.extend(sorted((root/'generated/web').glob('*')))
paths.extend(sorted((root/'dist').glob('*')))
pins=[{'path':str(p.relative_to(repo)),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths if p.is_file()]
raw_wasm=pathlib.Path(os.environ.get('CARGO_TARGET_DIR', str(repo/'target')))/'wasm32-unknown-unknown/release/mosaic_sdk_wasm.wasm'
raw_pin={'bytes':raw_wasm.stat().st_size,'sha256':hashlib.sha256(raw_wasm.read_bytes()).hexdigest()}
manifest={'unprocessed_release_wasm':raw_pin,'schema_version':1,'package':'@mosaic-private/sdk','version':'2.0.0','source_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=repo,text=True).strip()),'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'private':True,'wasm_bindgen':subprocess.check_output(['wasm-bindgen','--version'],text=True).strip(),'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'node':subprocess.check_output(['node','--version'],text=True).strip(),'pins':pins}
(root/'generated/build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
