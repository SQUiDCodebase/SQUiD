#pragma once

#include "tools.hpp"


namespace constants
{
    // DEBUG PARAMETERS

    const int DEBUG = 0;
    
    // BGV PARAMETERS
    const Params N15QP881(32768,65537, 1, 881);
    const Params N14QP438(16384,65537,  1, 438);
    const Params N13QP218(8192, 65537, 1, 218);
    const Params N12QP109(/*m=*/4096, /*p=*/65537, /*r=*/1, /*qbits=*/109);
    const Params P131(17293, 131, 1, 431);
}
