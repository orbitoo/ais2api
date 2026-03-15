const StreamZip = require('node-stream-zip');

async function testExtract() {
  try {
    const zip = new StreamZip.async({
        file: 'auth.zip',
        password: '123'  // Test password
    });
    
    const count = await zip.extract(null, './extracted');
    console.log(`Extracted ${count} entries`);
    await zip.close();
  } catch (e) {
    console.error("StreamZip Error:", e);
  }
}
testExtract();
