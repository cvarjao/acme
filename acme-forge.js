//openssl verify -verbose -CAfile ca0.cer ca1.cer

var fs = require('fs');
var forge = require('node-forge');



function _extend (origin, add) {
  // Don't do anything if add isn't an object
  if (!add || typeof add !== 'object') return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

/**
 * Copy properties from any number of other objects onto a target origin object.
 *
 * @param {Object} origin The object to copy properties onto.
 * @return {Object} The origin object.
 */
function extend (origin) {
  for (var i = 1, l = arguments.length; i < l; i++) {
    _extend(origin, arguments[i]);
  }
  return origin;
};

function _createCertificate(info){
  var cert = forge.pki.createCertificate();
  cert.publicKey = info.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject(info.subject);
  cert.setIssuer(info.issuer||info.subject);
  
  cert.setExtensions(info.extensions);
  // FIXME: add authorityKeyIdentifier extension
  return cert;
}

function _toSubjectObject(subject){
  if (!subject) return null;
  
  if (Array.isArray(subject)){
    var _subject={};
    for (var i = 0; i < subject.length; i++) {
      var item=subject[i];
      if (item.name=='commonName'){
        _subject.commonName=item.value;
      } else if (item.name=='countryName'){
        _subject.countryName=item.value;
      } else if (item.name=='stateOrProvinceName'){
        _subject.stateOrProvinceName=item.value;
      } else if (item.name=='localityName'){
        _subject.localityName=item.value;
      } else if (item.name=='organizationName'){
        _subject.organizationName=item.value;
      } else if (item.name=='organizationalUnitName'){
        _subject.organizationalUnitName=item.value;
      }
    }
    return _subject;
  }
  return subject;
}
function _toSubjectArray(subject){
  return [{
      name: 'commonName',
      value: subject.commonName
    }, {
      name: 'countryName',
      value: subject.countryName
    }, {
      shortName: 'ST',
      value: subject.stateOrProvinceName
    }, {
      name: 'localityName',
      value: subject.localityName
    }, {
      name: 'organizationName',
      value: subject.organizationName
    }, {
      shortName: 'OU',
      value: subject.organizationalUnitName
    }];
}
function _createCert(keyPair, info){
  var __subject={commonName:'ca.example.org', countryName:'US', stateOrProvinceName:'Virginia', localityName:'Blacksburg', organizationName:'Test', organizationalUnitName:'Test'};
  var __extKeyUsage={keyCertSign: true,digitalSignature: true,nonRepudiation: true,keyEncipherment: true, dataEncipherment: true};
  var __extExtKeyUsage={serverAuth: true, clientAuth: true, codeSigning: true, emailProtection: true, timeStamping: true};
  var __extNsCertType={client: true, server: true, email: true, objsign: true, sslCA: true, emailCA: true, objCA: true};
  
  var _info=info||{};
  var _extensions=_info.extensions||{};
  var _subject=extend({}, __subject, _toSubjectObject(_info.subject));
  var _issuer=_toSubjectObject(_info.issuer)||_subject;
  
  var _extKeyUsage=extend({name: 'keyUsage'}, __extKeyUsage, _extensions.keyUsage);
  var _extExtKeyUsage=extend({name: 'extKeyUsage'}, __extExtKeyUsage, _extensions.extKeyUsage);
  var _extNsCertType=extend({name: 'nsCertType'}, __extNsCertType, _extensions.nsCertType);
  
  ca0Subject=_toSubjectArray(_subject);
  ca0Issuer=_toSubjectArray(_issuer);
  
  ca0Extensions=[_extKeyUsage, _extExtKeyUsage, _extNsCertType, {
    name: 'subjectAltName',
    altNames: [{
      type: 6, // URI
      value: 'http://example.org/webid#me'
    }, {
      type: 7, // IP
      ip: '127.0.0.1'
    }]
  }, {
    name: 'subjectKeyIdentifier'
  }];
  
  cert=_createCertificate({subject:ca0Subject, issuer:ca0Issuer, publicKey:keyPair.publicKey, extensions:ca0Extensions});
  cert.sign(keyPair.privateKey/*, forge.md.sha256.create()*/);
  return cert;
}
function _createRootCA(keyPair, info){
  var __subject={commonName:'ca.example.org', countryName:'US', stateOrProvinceName:'Virginia', localityName:'Blacksburg', organizationName:'Test', organizationalUnitName:'Test'};
  var __extBasicConstraints={cA:true};
  var __extKeyUsage={keyCertSign: true,digitalSignature: true,nonRepudiation: true,keyEncipherment: true, dataEncipherment: true};
  var __extExtKeyUsage={serverAuth: true, clientAuth: true, codeSigning: true, emailProtection: true, timeStamping: true};
  var __extNsCertType={client: true, server: true, email: true, objsign: true, sslCA: true, emailCA: true, objCA: true};
  
  var _info=info||{};
  var _extensions=_info.extensions||{};
  var _subject=extend({}, __subject, _toSubjectObject(_info.subject));
  var _issuer=_toSubjectObject(_info.issuer)||_subject;
  
  var _extBasicConstraints=extend({name: 'basicConstraints'}, __extBasicConstraints, _extensions.basicConstraints);
  var _extKeyUsage=extend({name: 'keyUsage'}, __extKeyUsage, _extensions.keyUsage);
  var _extExtKeyUsage=extend({name: 'extKeyUsage'}, __extExtKeyUsage, _extensions.extKeyUsage);
  var _extNsCertType=extend({name: 'nsCertType'}, __extNsCertType, _extensions.nsCertType);
  
  ca0Subject=_toSubjectArray(_subject);
  ca0Issuer=_toSubjectArray(_issuer);
  
  ca0Extensions=[_extBasicConstraints, _extKeyUsage, _extExtKeyUsage, _extNsCertType, {
    name: 'subjectAltName',
    altNames: [{
      type: 6, // URI
      value: 'http://example.org/webid#me'
    }, {
      type: 7, // IP
      ip: '127.0.0.1'
    }]
  }, {
    name: 'subjectKeyIdentifier'
  }];
  
  cert=_createCertificate({subject:ca0Subject, issuer:ca0Issuer, publicKey:keyPair.publicKey, extensions:ca0Extensions});
  cert.sign(keyPair.privateKey/*, forge.md.sha256.create()*/);
  return cert;
}
exports.createChain = (certs) => {
  console.log('Generating 1024-bit key-pair...');
  //var certs=[];
  
  for (var i = 0; i < 2; i++) {
    var ca0Keypair = {publicKey:null, privateKey:null};
    var ca0PrivaKeyFile="ca"+i+".private.key"
    var ca0PublicKey="ca"+i+".public.key"
    var ca0CertFile="ca"+i+".cer"
    var ca0ChainCertFile="ca"+i+".chain.pem"
    
    if (fs.existsSync(ca0PrivaKeyFile)){
      console.log("Loading Private key ("+i+")");
      var _content=fs.readFileSync(ca0PrivaKeyFile);
      ca0Keypair.privateKey=forge.pki.privateKeyFromPem(_content);
    }
    
    if (fs.existsSync(ca0PublicKey)){
      console.log("Loading Public key ("+i+")");
      var _content=fs.readFileSync(ca0PublicKey);
      ca0Keypair.publicKey=forge.pki.publicKeyFromPem(_content);
    }
    
    if (ca0Keypair.publicKey===null && ca0Keypair.privateKey===null){
      console.log("Generating Key pair ("+i+")");
      ca0Keypair=forge.pki.rsa.generateKeyPair(1024);
      forge.pki.publicKeyToPem(ca0Keypair.publicKey);
      fs.writeFile(ca0PrivaKeyFile, forge.pki.privateKeyToPem(ca0Keypair.privateKey));
      fs.writeFile(ca0PublicKey, forge.pki.publicKeyToPem(ca0Keypair.publicKey));
    }
    //ca0Keypair.publicKey;
    //ca0Keypair.privateKey;
    
    var cert=null;
    if (i==0){
      console.log("Generating Root CA");
      cert=_createRootCA(ca0Keypair);

      // self-sign certificate
      cert.sign(ca0Keypair.privateKey/*, forge.md.sha256.create()*/);
      
      
      console.log('Root CA created.');
    }else{
      var _issuerCert=certs[i-1]
      //console.log(Array.isArray(_issuerCert.certificate.subject.attributes));
      console.log("Generating Intermediate CA ("+i+")");
      cert=_createRootCA(ca0Keypair, {subject:{commonName:'Intermediate CA'}, issuer:_issuerCert.certificate.subject.attributes, extensions:{basicConstraints:{pathLenConstraint:0}}});

      // self-sign certificate
      cert.sign(_issuerCert.privateKey/*, forge.md.sha256.create()*/);
      console.log('Intermediate CA created.');
    }
    
    pem=forge.pki.certificateToPem(cert);
    fs.writeFileSync(ca0CertFile, pem);
    certs.push({privateKey:ca0Keypair.privateKey, publicKey:ca0Keypair.publicKey, certificate:cert, pemChanFile:ca0ChainCertFile});
    
    if (fs.existsSync(ca0ChainCertFile)) fs.truncateSync(ca0ChainCertFile, 0);
    
    for (var j= 0; j < certs.length; j++) {
      console.log('Writing Chain ('+j+')');
      fs.appendFileSync(ca0ChainCertFile, forge.pki.certificateToPem(certs[j].certificate));
    }
  }
  return certs;
}
exports.newCert = (chain, info) => {
  var ca0PrivaKeyFile="ca1.private.key"
  var ca0CertFile="ca1.cer"
  var issuerPrivateKey=forge.pki.privateKeyFromPem(fs.readFileSync(ca0PrivaKeyFile));
  var issuerCert = forge.pki.certificateFromPem(fs.readFileSync(ca0CertFile));
  
  var _issuerCert=chain[chain.length-1]
  var keypair=forge.pki.rsa.generateKeyPair(1024);
  var cert=_createCert(keypair, {subject:{commonName:'Some device'}, issuer:issuerCert.subject.attributes, extensions:{basicConstraints:{pathLenConstraint:0}}});
  cert.sign(issuerPrivateKey/*, forge.md.sha256.create()*/);
  var pem=forge.pki.certificateToPem(cert);
  
  fs.writeFileSync("cert.last.cer", pem);
  return {privateKey:forge.pki.privateKeyToPem(keypair.privateKey), publicKey:forge.pki.publicKeyToPem(keypair.publicKey), certificate:pem}
}
