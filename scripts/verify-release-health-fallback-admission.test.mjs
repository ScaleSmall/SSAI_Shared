import assert from 'node:assert/strict';
import { canonicalFallbackEnvelope, encodeFallbackEnvelope, fallbackSlotClaimKey, signFallbackEnvelope, validateFallbackAdmission } from './verify-release-health-fallback-admission.mjs';
const key=Buffer.alloc(32,9).toString('base64'),slot=29_817_121,issued=slot*60+601;
const envelope={version:'ssai-release-health-fallback-v1',repository:'ScaleSmall/SSAI_Shared',repository_id:'1183552904',workflow_id:'344170407',workflow_path:'.github/workflows/release-health-monitor-fallback.yml',ref:'refs/heads/main',expected_sha:'a'.repeat(40),slot_epoch_minute:String(slot),request_id:'b'.repeat(32),issued_at_epoch_second:String(issued),expires_at_epoch_second:String(issued+299)};
const input={envelope_base64url:encodeFallbackEnvelope(envelope),slot_epoch_minute:envelope.slot_epoch_minute,request_id:envelope.request_id,signature_sha256:signFallbackEnvelope(envelope,key)};
const providerRun={id:400,run_attempt:1,workflow_id:344170407,event:'workflow_dispatch',path:'.github/workflows/release-health-monitor-fallback.yml@refs/heads/main',repository:{id:1183552904,full_name:'ScaleSmall/SSAI_Shared'},head_branch:'main',head_sha:envelope.expected_sha,actor:{login:'app[bot]',id:22},triggering_actor:{id:22}};
const context={repository:'ScaleSmall/SSAI_Shared',repositoryId:1183552904,workflowId:344170407,workflowPath:'.github/workflows/release-health-monitor-fallback.yml',ref:'refs/heads/main',event:'workflow_dispatch',sha:envelope.expected_sha,workflowSha:envelope.expected_sha,refProtected:true,runAttempt:1,runId:400,actorLogin:'app[bot]',expectedActorLogin:'app[bot]',actorId:22,expectedActorId:22,senderId:22,expectedSenderId:22,providerRun};
assert.equal(validateFallbackAdmission(input,context,key,issued+10).request_id,input.request_id);
assert.equal(fallbackSlotClaimKey(input.slot_epoch_minute,key),fallbackSlotClaimKey(input.slot_epoch_minute,key));
for(const field of Object.keys(envelope)){const mutated={...envelope,[field]:envelope[field]+'x'};assert.throws(()=>validateFallbackAdmission({...input,envelope_base64url:encodeFallbackEnvelope(mutated)},context,key,issued+10),undefined,field+' mutation must fail authentication')}
for(const bad of [{...input,slot_epoch_minute:String(slot+1)},{...input,request_id:'c'.repeat(32)},{...input,signature_sha256:'0'.repeat(64)},{...input,envelope_base64url:input.envelope_base64url+'A'}])assert.throws(()=>validateFallbackAdmission(bad,context,key,issued+10));
for(const mutation of [{path:'.github/workflows/wrong.yml'},{repository:{id:1,full_name:'ScaleSmall/SSAI_Shared'}},{run_attempt:2}])assert.throws(()=>validateFallbackAdmission(input,{...context,providerRun:{...providerRun,...mutation}},key,issued+10),/provenance/);
assert.throws(()=>validateFallbackAdmission(input,{...context,runAttempt:2},key,issued+10),/runAttempt/);
assert.throws(()=>validateFallbackAdmission(input,context,key,slot*60+900),/validity window/);
assert.throws(()=>validateFallbackAdmission(input,{...context,refProtected:false},key,issued+10),/refProtected/);
const extra=Buffer.concat([canonicalFallbackEnvelope(envelope),Buffer.from([0])]).toString('base64url');assert.throws(()=>validateFallbackAdmission({...input,envelope_base64url:extra},context,key,issued+10));
assert.throws(()=>signFallbackEnvelope(envelope,Buffer.alloc(129).toString('base64')),/key is invalid/);
console.log('Release-health fallback admission tests passed.');
