// Original procedural AI busts. Geometry only; no downloaded models or textures.
import * as THREE from 'three';

export const ROBOT_VARIANTS = ['android','visor','cyclops','oracle','neural-core','facet','twin-halo','synapse','sentient','spectre'];

export function buildRobotAvatar(parent, variant='android', {lowPower=false,reduceMotion=false,surfaceStyle=null}={}) {
  if(!ROBOT_VARIANTS.includes(variant))variant='android';
  const root=new THREE.Group();root.name='ai-bust-'+variant;parent.add(root);
  const resources=new Set(), materials=[], moving=[];
  const track=o=>{resources.add(o);return o;};
  // Geometry variants share the exact ridge surface supplied by the human head scene.
  // These blue templates only tag geometry parts; no metallic/Phong robot skin is used.
  function material(kind='shell',opacity=1){
    const m=track(new THREE.MeshBasicMaterial({color:0x62d9ff,transparent:true,opacity,depthWrite:false}));
    m.userData.contourSurface=kind==='shell';
    materials.push([m,kind,opacity]);return m;
  }
  const shell=material(),dark=material('dark'),metal=material('metal'),glow=material('glow'),ghost=material('ghost',.16);
  const occlusion=track(new THREE.MeshBasicMaterial({colorWrite:false,polygonOffset:true,polygonOffsetFactor:1,polygonOffsetUnits:1}));
  function mesh(geometry,mat,pos=[0,0,0],scale=[1,1,1],rot=[0,0,0],group=root){
    const o=new THREE.Mesh(track(geometry),mat);o.position.set(...pos);o.scale.set(...scale);o.rotation.set(...rot);group.add(o);
    if(surfaceStyle&&mat.userData.contourSurface){
      o.updateMatrix();
      // Sample the contour field in bust coordinates, so stripes continue across
      // separately scaled face/shoulder parts and rotate with the whole identity.
      const skin=track(new THREE.ShaderMaterial({
        uniforms:{...surfaceStyle.uniforms,uAvatarMatrix:{value:o.matrix}},
        vertexShader:surfaceStyle.vertexShader,fragmentShader:surfaceStyle.fragmentShader,
        transparent:true,depthWrite:false,blending:surfaceStyle.blending,
      }));
      o.material=skin;o.userData.ridgeSurface=true;materials.push([skin,'ridge',1]);
      const depth=new THREE.Mesh(geometry,occlusion);depth.renderOrder=-1;o.add(depth);
    }
    return o;
  }
  const sphere=(mat,pos,scale,detail=24)=>mesh(new THREE.SphereGeometry(1,lowPower?16:detail,lowPower?12:20),mat,pos,scale);
  const box=(mat,pos,scale,rot=[0,0,0])=>mesh(new THREE.BoxGeometry(1,1,1),mat,pos,scale,rot);
  function ring(radius,tube,pos,rot=[0,0,0],mat=glow){return mesh(new THREE.TorusGeometry(radius,tube,6,lowPower?32:56),mat,pos,[1,1,1],rot);}
  function line(points,mat=glow,radius=.009,closed=false){
    const curve=new THREE.CatmullRomCurve3(points.map(p=>new THREE.Vector3(...p)),closed);
    return mesh(new THREE.TubeGeometry(curve,lowPower?20:40,radius,4,closed),mat);
  }
  function polygon(points,depth,mat,pos=[0,0,0],bevel=.025){
    const shape=new THREE.Shape();points.forEach(([x,y],i)=>i?shape.lineTo(x,y):shape.moveTo(x,y));shape.closePath();
    const g=new THREE.ExtrudeGeometry(shape,{depth,steps:1,bevelEnabled:bevel>0,bevelSegments:2,bevelSize:bevel,bevelThickness:bevel});
    g.translate(0,0,-depth/2);return mesh(g,mat,pos);
  }
  function contour(y,rx,rz,z=0,mat=glow){
    const pts=[];for(let i=0;i<48;i++){const a=i/48*Math.PI*2;pts.push([Math.cos(a)*rx,y,Math.sin(a)*rz+z]);}
    return line(pts,mat,.008,true);
  }
  // Common neck, clavicles and shoulder silhouette connect every variant to the existing bust design.
  if(variant!=='spectre'&&variant!=='synapse'){
    mesh(new THREE.CylinderGeometry(.18,.27,.42,20),shell,[0,-.35,0]);
    for(const y of [-.23,-.34,-.45])ring(.19,.014,[0,y,0],[Math.PI/2,0,0]);
    // A single smooth shoulder surface keeps the contour silhouette continuous.
    sphere(shell,[0,-.92,-.035],[1.02,.38,.34]);
    line([[-.68,-.69,.23],[-.3,-.61,.29],[0,-.69,.32],[.3,-.61,.29],[.68,-.69,.23]],glow,.008);

  }else{
    for(let j=0;j<12;j++){let t=j/11;contour(-1.18+t*.64,.48+Math.sin(t*Math.PI)*.5,.25+t*.05);}
    for(let j=0;j<4;j++)contour(-.5+j*.08,.19,.19);
  }
  const cheeks=()=>{for(const side of [-1,1])line([[side*.36,.34,.30],[side*.37,.12,.29],[side*.22,-.02,.31]],glow,.006);};
  const eyes=(y=.47,z=.37)=>{for(const s of [-1,1]){
    sphere(dark,[s*.235,y,z],[.16,.055,.025]);
    sphere(glow,[s*.235,y,z+.024],[.125,.019,.02]);
  }};
  const ears=()=>{for(const s of [-1,1]){
    mesh(new THREE.CylinderGeometry(.18,.18,.13,24),dark,[s*.49,.43,0],[1,1,1],[0,0,Math.PI/2]);
    ring(.137,.018,[s*.56,.43,0],[0,Math.PI/2,0]);
  }};
  const face=()=>{
    sphere(shell,[0,.51,-.035],[.48,.64,.42]);
    polygon([[-.045,.13],[.045,.13],[.08,-.09],[0,-.14],[-.08,-.09]],.08,metal,[0,.36,.44]);
    line([[-.12,-.035,.36],[0,-.05,.39],[.12,-.035,.36]],dark,.012);
  };
  if(['android','oracle','twin-halo'].includes(variant)){
    face();eyes();cheeks();ears();
    line([[0,1.13,-.08],[0,1.08,.18],[0,.91,.35],[0,.77,.39]],glow,.009);
    if(variant==='oracle'){
      for(const s of [-1,1])polygon([[s*.08,.05],[s*.23,.32],[s*.48,.39],[s*.35,.08]],.09,metal,[0,.8,.02]);
      ring(.082,.012,[0,.84,.36]);
    }
    if(variant==='twin-halo')for(const [y,tilt] of [[.88,.22],[.16,-.22]]){
      const r=ring(.74,.014,[0,y,0],[Math.PI/2,tilt,.18]);moving.push([r,'halo']);
      sphere(glow,[.74,y,0],[.035,.035,.035]);
    }
  }else if(variant==='visor'){
    sphere(shell,[0,.5,0],[.49,.64,.43]);
    polygon([[-.49,.28],[.49,.28],[.42,-.12],[.17,-.47],[-.17,-.47],[-.42,-.12]],.12,metal,[0,.48,.34]);
    box(dark,[0,.55,.44],[.91,.16,.09]);
    line([[-.44,.55,.43],[-.2,.53,.51],[0,.53,.54],[.2,.53,.51],[.44,.55,.43]],glow,.026);
    ears();line([[-.15,.13,.43],[0,.05,.46],[.15,.13,.43]],dark,.018);
  }else if(variant==='cyclops'){
    sphere(shell,[0,.5,0],[.53,.63,.46]);
    sphere(dark,[0,.5,.4],[.44,.44,.15]);
    for(const [r,z] of [[.36,.49],[.28,.54],[.17,.57]])ring(r,.016,[0,.5,z]);
    sphere(glow,[0,.5,.56],[.12,.12,.045]);
  }else if(variant==='neural-core'){
    mesh(new THREE.IcosahedronGeometry(.31,1),glow,[0,.5,0]);
    for(let i=0;i<3;i++){
      const r=ring(.54+i*.065,.018,[0,.5,0],[.8+i*.65,.3+i*.7,0],i===1?metal:glow);moving.push([r,'core',i]);
    }
    for(let i=0;i<10;i++){
      const a=i/10*Math.PI*2;
      line([[Math.cos(a)*.67,.5+Math.sin(a)*.67,0],[Math.cos(a)*.79,.5+Math.sin(a)*.79,0]],metal,.018);
      sphere(glow,[Math.cos(a)*.8,.5+Math.sin(a)*.8,0],[.035,.035,.035]);
    }
  }else if(variant==='facet'){
    mesh(new THREE.IcosahedronGeometry(.63,1),shell,[0,.5,0],[.8,1.13,.77]);
    polygon([[-.37,.2],[0,.12],[.37,.2],[.23,-.24],[0,-.4],[-.23,-.24]],.1,shell,[0,.27,.35],0);
    eyes(.51,.435);cheeks();
    for(const s of [-1,1])polygon([[0,.15],[s*.34,.28],[s*.45,-.05],[s*.25,-.18]],.08,dark,[0,.78,.12],0);
  }else if(variant==='sentient'){
    polygon([[-.38,.5],[.38,.5],[.53,.35],[.53,-.2],[.32,-.38],[-.32,-.38],[-.53,-.2],[-.53,.35]],.5,shell,[0,.45,0],.06);
    box(dark,[0,.46,.31],[.85,.45,.08]);
    for(const s of [-1,1]){
      ring(.147,.022,[s*.235,.49,.37]);ring(.09,.012,[s*.235,.49,.38]);
      sphere(glow,[s*.235,.49,.39],[.05,.06,.02]);
      line([[s*.42,.92,0],[s*.5,1.19,-.04]],metal,.026);
      sphere(glow,[s*.5,1.19,-.04],[.04,.04,.04]);
    }
    ears();box(glow,[0,.2,.3],[.16,.013,.02]);
  }else if(variant==='synapse'){
    const geometry=track(new THREE.IcosahedronGeometry(1,lowPower?2:3));
    geometry.scale(.48,.66,.42);geometry.translate(0,.5,0);
    mesh(geometry,ghost);
    const edges=track(new THREE.EdgesGeometry(geometry,1));
    const lineMat=track(new THREE.LineBasicMaterial({transparent:true,opacity:.65,color:0x64caff}));materials.push([lineMat,'line',.65]);
    root.add(new THREE.LineSegments(edges,lineMat));
    const positions=geometry.attributes.position;
    const pts=[];for(let i=0;i<positions.count;i+=lowPower?15:18)pts.push(positions.getX(i),positions.getY(i),positions.getZ(i));
    const pg=track(new THREE.BufferGeometry());pg.setAttribute('position',new THREE.Float32BufferAttribute(pts,3));
    const pm=track(new THREE.PointsMaterial({color:0x91eaff,size:.018,transparent:true}));materials.push([pm,'glow',1]);root.add(new THREE.Points(pg,pm));
    eyes(.48,.44);line([[0,.68,.42],[0,.35,.49],[.07,.26,.45]],glow,.012);
  }else if(variant==='spectre'){
    for(let j=0;j<29;j++){
      const y=-.12+j*.047,t=(y-.5)/.71,rx=.48*Math.sqrt(Math.max(.01,1-t*t));
      const pts=[];for(let i=0;i<48;i++){
        const a=i/48*Math.PI*2;let z=Math.sin(a)*.4*Math.sqrt(Math.max(.01,1-t*t));
        // A slight central nose projection preserves a recognisable face silhouette.
        z+=Math.exp(-Math.pow((a-Math.PI/2)*7,2))*Math.exp(-Math.pow((y-.33)*7,2))*.13;
        pts.push([Math.cos(a)*rx,y,z]);
      }
      line(pts,glow,.008,true);
    }
    eyes(.49,.39);line([[0,1.12,0],[0,.9,.25],[0,.65,.39]],glow,.013);
  }
  // Sparse surface nodes and short neural connections repeat the human identity's
  // visual language without hiding each variant's silhouette under solid plates.
  if(surfaceStyle){
    const candidates=[],seen=new Set();
    root.traverse(o=>{
      if(!o.userData.ridgeSurface)return;
      const positions=o.geometry.attributes.position;
      for(let i=0;i<positions.count;i+=Math.max(1,Math.ceil(positions.count/10))){
        const point=new THREE.Vector3().fromBufferAttribute(positions,i).applyMatrix4(o.matrix);
        if(point.y<-.45)continue;
        const key=[point.x,point.y,point.z].map(v=>v.toFixed(2)).join(':');
        if(!seen.has(key)){seen.add(key);candidates.push(point);}
      }
    });
    const budget=lowPower?45:85;
    const points=candidates.filter((_,i)=>i%Math.max(1,Math.ceil(candidates.length/budget))===0).slice(0,budget);
    const geometry=track(new THREE.BufferGeometry().setFromPoints(points));
    const dots=track(new THREE.PointsMaterial({color:0x91eaff,size:.018,transparent:true,depthWrite:false,blending:surfaceStyle.blending}));
    materials.push([dots,'glow',1]);root.add(new THREE.Points(geometry,dots));
    const links=[];
    points.forEach((point,i)=>{
      let count=0;
      for(let j=i+1;j<points.length&&count<2;j++)if(point.distanceToSquared(points[j])<.25*.25){links.push(point,points[j]);count++;}
    });
    const linkGeometry=track(new THREE.BufferGeometry().setFromPoints(links));
    const linkMaterial=track(new THREE.LineBasicMaterial({color:0x62d9ff,transparent:true,opacity:.18,depthWrite:false,blending:surfaceStyle.blending}));
    materials.push([linkMaterial,'line',.18]);root.add(new THREE.LineSegments(linkGeometry,linkMaterial));
  }
  const red=new THREE.Color(0xff354e);
  function update(time,alert=0,activity=0,light=false,paused=false){
    for(const [m,kind,opacity] of materials){
      const blending=light?THREE.NormalBlending:THREE.AdditiveBlending;
      if(m.transparent&&m.blending!==blending){m.blending=blending;m.needsUpdate=true;}
      // Shared ridge uniforms are advanced by the scene, just like the human head.
      if(m.isShaderMaterial)continue;
      const color=kind==='glow'||kind==='line'?(light?0x1761d9:0x62d9ff):kind==='dark'?(light?0x25406a:0x0a1d39):kind==='metal'?(light?0x3467a4:0x173855):(light?0x3467a4:0x173855);
      m.color.setHex(color).lerp(red,Math.min(1,alert)*.85);
      if(m.emissive){m.emissive.copy(m.color);m.emissiveIntensity=kind==='glow'?.65+activity*.7:.04+alert*.15;}
      if(m.isLineBasicMaterial)m.opacity=light?opacity*.7:opacity;
    }
    if(!reduceMotion&&!paused)for(const [o,type,i=0] of moving){
      if(type==='core'){o.rotation.x=.8+i*.65+time*.12;o.rotation.y=.3+i*.7+time*.17;}
      if(type==='halo')o.rotation.z=time*.12;
      if(type==='plate')o.position.z=.3+Math.sin(time*.55+i)*.015;
    }
  }
  update(0);
  return {root,variant,update,dispose(){parent.remove(root);resources.forEach(o=>o.dispose());root.clear();}};
}
