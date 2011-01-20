/**
 * @file   GridProxyType.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class GridProxyType
 *
 */
/*
 * Copyright (c) 2010-2011 ETH Zurich and University of Zurich.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ch.swing.gridcertlib;

import org.glite.voms.contact.VOMSProxyBuilder;

/** Enumeration of the Grid Proxy types (GT2, GT3, GT4).
 * For more information on GSI proxy certificate types,
 * see: <a href="http://dev.globus.org/wiki/Security/ProxyCertTypes">
 *   http://dev.globus.org/wiki/Security/ProxyCertTypes
 * </a>
 * <p>
 * This class exists mainly to work around a bug in VOMS Java API 1.9.17,
 * where setting the proxy type to an incorrect value, will raise
 * a NullPointerException in {org.glite.voms.contact.VOMSProxyBuilder#myCreateVomsProxy}
 * 
 */

public final class GridProxyType {
    private final int type_;
    private GridProxyType(final int type) { type_ = type; }
    /* package-private */ int proxyType() { return type_; }

    /** The default proxy type defined in the VOMS Java API. */
    public static final GridProxyType Default = new GridProxyType(VOMSProxyBuilder.DEFAULT_PROXY_TYPE);

    /** Legacy (Globus Toolkit 2) proxy type. */
    public static final GridProxyType GT2 = new GridProxyType(VOMSProxyBuilder.GT2_PROXY);

    /** GSI3 Proxy certificates (draft standard proxies). */
    public static final GridProxyType GT3 = new GridProxyType(VOMSProxyBuilder.GT3_PROXY);

    /** RFC3820 standard proxy certificates. */
    public static final GridProxyType GT4 = new GridProxyType(VOMSProxyBuilder.GT4_PROXY);

    /** RFC3820 standard proxy certificates. */
    public static final GridProxyType RFC3820 = new GridProxyType(VOMSProxyBuilder.GT4_PROXY);
}
