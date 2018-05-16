/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.spi;

import javax.xml.datatype.Duration;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;
import java.util.zip.ZipException;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.Saml2Object;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.zip.Deflater.DEFLATED;

public abstract class SpringSecuritySaml<T extends SpringSecuritySaml> {

    private final AtomicBoolean hasInitCompleted = new AtomicBoolean(false);

    private Base64 UNCHUNKED_ENCODER = new Base64(0, new byte[]{'\n'});

    @SuppressWarnings("checked")
    public T init() {
        if (!hasInitCompleted.get()) {
            performInit();
        }
        return (T) this;
    }

    protected synchronized void performInit() {
        if (hasInitCompleted.compareAndSet(false, true)) {
            java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
            );
            bootstrap();
        }
    }

    public long durationToMillis(Duration duration) {
        return toMillis(duration);
    }

    public Duration millisToDuration(long millis) {
        return toDuration(millis);
    }

    protected abstract void bootstrap();

    public abstract long toMillis(Duration duration);

    public abstract Duration toDuration(long millis);

    public abstract String toXml(Saml2Object saml2Object);

    public abstract Saml2Object resolve(String xml, List<SimpleKey> trustedKeys);

    public abstract Saml2Object resolve(byte[] xml, List<SimpleKey> trustedKeys);

    public String deflateAndEncode(String s) {
//        try {
//            ByteArrayOutputStream b = new ByteArrayOutputStream();
//            DeflaterOutputStream deflater = new DeflaterOutputStream(b, new Deflater(DEFLATED, true));
//            deflater.write(s.getBytes(UTF_8));
//            deflater.finish();
//            return UNCHUNKED_ENCODER.encodeToString(b.toByteArray());
            return UNCHUNKED_ENCODER.encodeToString(s.getBytes(UTF_8));
//        } catch (IOException e) {
//            throw new RuntimeException("Unable to deflate and base64 encode string", e);
//        }
    }

    public String decodeAndInflate(String s) {
        byte[] b = UNCHUNKED_ENCODER.decode(s);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
            iout.write(b);
            iout.finish();
            return new String(out.toByteArray(), UTF_8);
        } catch (ZipException e) {
            //no inflation/deflation used?
            return new String(b, UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Unable to deflate and base64 encode string", e);
        }
    }


}
