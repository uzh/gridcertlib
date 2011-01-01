/**
 * @file   GridProxyType.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class GridProxyType
 *
 */
/* 
 * Copyright (c) 2010, ETH Zurich and University of Zurich.  All rights reserved.
 * 
 * This file is part of the GridCertLib software project.
 * You may copy, distribute and modify this file under the terms of
 * the LICENSE.txt file at the root of the project directory tree.
 *
 * $Id$
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
